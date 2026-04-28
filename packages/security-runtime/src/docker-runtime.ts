// packages/security-runtime/src/docker-runtime.ts
import { randomBytes } from "node:crypto";
import { posix as pathPosix } from "node:path";
import { PassThrough } from "node:stream";
import Dockerode from "dockerode";
import { SandboxInitializationError } from "./errors.js";
import type { CreateWorkspaceInput, ExecOptions, ExecResult, SecurityRuntime, WorkspaceHandle } from "./runtime.js";

const CONTAINER_WORKSPACE_PATH = "/workspace";
const DEFAULT_IMAGE = process.env.NYATI_SANDBOX_IMAGE ?? "nyati-sandbox:latest";
const EXEC_PID_MARKER = "__NYATI_PID__=";
const SCOPE_TARGETS_PATH = `${CONTAINER_WORKSPACE_PATH}/.nyati/targets.json`;
const SHELL_SINGLE_QUOTE_ESCAPE = `'"'"'`;

function shellEscape(value: string): string {
	if (value.length === 0) {
		return "''";
	}

	return `'${value.replaceAll("'", SHELL_SINGLE_QUOTE_ESCAPE)}'`;
}

export function buildExecCommand(command: string): string[] {
	return ["sh", "-lc", `printf '${EXEC_PID_MARKER}%s\\n' "$$" >&2; exec sh -lc "$1"`, "sh", command];
}

export function stripExecPidMarker(stderr: string): { pid: number | null; stderr: string } {
	const match = stderr.match(new RegExp(`^${EXEC_PID_MARKER}(\\d+)\\r?\\n?`));
	if (!match) {
		return { pid: null, stderr };
	}

	return {
		pid: Number(match[1]),
		stderr: stderr.slice(match[0].length),
	};
}

export function buildSyncTargetsCommand(targets: unknown[]): string {
	const content = JSON.stringify({ syncedAt: new Date().toISOString(), targets }, null, 2);
	const targetDir = pathPosix.dirname(SCOPE_TARGETS_PATH);
	return `mkdir -p ${shellEscape(targetDir)} && printf '%s' ${shellEscape(content)} > ${shellEscape(SCOPE_TARGETS_PATH)}`;
}

export class DockerSecurityRuntime implements SecurityRuntime {
	private docker: Dockerode;
	private containers = new Map<string, Dockerode.Container>();

	constructor(socketPath?: string) {
		this.docker = socketPath ? new Dockerode({ socketPath }) : new Dockerode();
	}

	async createWorkspace(input: CreateWorkspaceInput): Promise<WorkspaceHandle> {
		const { agentId, localSources = [], envVars = {}, capAdd = [] } = input;
		const containerName = `nyati-${agentId.slice(0, 8)}-${randomBytes(4).toString("hex")}`;

		try {
			await this.docker.getImage(DEFAULT_IMAGE).inspect();
		} catch {
			throw new SandboxInitializationError(
				"Docker image not found",
				`Build or pull '${DEFAULT_IMAGE}' before starting a security session.`,
			);
		}

		const container = await this.docker.createContainer({
			Image: DEFAULT_IMAGE,
			name: containerName,
			Cmd: ["sleep", "infinity"],
			Tty: true,
			Env: Object.entries(envVars).map(([k, v]) => `${k}=${v}`),
			Labels: { "nyati-agent-id": agentId },
			HostConfig: capAdd.length > 0 ? { CapAdd: capAdd } : {},
		});

		await container.start();

		const info = await container.inspect();
		const containerId = info.Id;
		this.containers.set(containerId, container);

		if (localSources.length > 0) {
			await this.copySourcesToContainer(container, localSources);
		}

		return {
			workspaceId: containerId,
			containerId,
			workspacePath: CONTAINER_WORKSPACE_PATH,
		};
	}

	private async copySourcesToContainer(
		container: Dockerode.Container,
		sources: Array<{ sourcePath: string; workspaceSubdir?: string }>,
	): Promise<void> {
		for (const { workspaceSubdir } of sources) {
			const targetPath = workspaceSubdir
				? `${CONTAINER_WORKSPACE_PATH}/${workspaceSubdir}`
				: CONTAINER_WORKSPACE_PATH;
			const exec = await container.exec({
				Cmd: ["mkdir", "-p", targetPath],
				AttachStdout: false,
				AttachStderr: false,
			});
			await exec.start({ hijack: false, stdin: false });
		}
		// Full tar-streaming copy is a Phase 2 enhancement.
	}

	private async terminateExecProcess(container: Dockerode.Container, pid: number): Promise<void> {
		if (!Number.isInteger(pid) || pid <= 0) {
			return;
		}

		const killExec = await container.exec({
			Cmd: ["sh", "-lc", `kill -TERM ${pid} 2>/dev/null || true; sleep 1; kill -KILL ${pid} 2>/dev/null || true`],
			AttachStdout: false,
			AttachStderr: false,
		});
		await killExec.start({ hijack: false, stdin: false });
	}

	async destroyWorkspace(workspaceId: string): Promise<void> {
		const container = this.containers.get(workspaceId);
		if (!container) {
			try {
				const c = this.docker.getContainer(workspaceId);
				await c.stop({ t: 5 }).catch(() => {});
				await c.remove({ force: true }).catch(() => {});
			} catch {
				// Container already gone
			}
			return;
		}
		try {
			await container.stop({ t: 5 }).catch(() => {});
			await container.remove({ force: true }).catch(() => {});
		} finally {
			this.containers.delete(workspaceId);
		}
	}

	async syncTargets(workspaceId: string, targets: unknown[]): Promise<void> {
		const result = await this.execInContainer(workspaceId, buildSyncTargetsCommand(targets));
		if (result.exitCode !== 0) {
			throw new Error(`Failed to sync targets into container: ${result.stderr || result.stdout}`);
		}
	}

	cleanup(): void {
		for (const [id, container] of this.containers) {
			container.stop({ t: 3 }).catch(() => {});
			container.remove({ force: true }).catch(() => {});
			this.containers.delete(id);
		}
	}

	async execInContainer(workspaceId: string, command: string, options?: ExecOptions): Promise<ExecResult> {
		const container = this.containers.get(workspaceId) ?? this.docker.getContainer(workspaceId);

		const exec = await container.exec({
			Cmd: buildExecCommand(command),
			AttachStdout: true,
			AttachStderr: true,
			WorkingDir: options?.workingDir ?? CONTAINER_WORKSPACE_PATH,
		});

		const stdoutChunks: Buffer[] = [];
		const stderrChunks: Buffer[] = [];
		const stdoutStream = new PassThrough();
		const stderrStream = new PassThrough();
		stdoutStream.on("data", (chunk: Buffer) => {
			stdoutChunks.push(chunk);
		});
		stderrStream.on("data", (chunk: Buffer) => {
			stderrChunks.push(chunk);
		});

		const stream = await exec.start({ hijack: true, stdin: false });

		await new Promise<void>((resolve, reject) => {
			let settled = false;
			let timeoutId: ReturnType<typeof setTimeout> | undefined;

			const resolveOnce = () => {
				if (settled) return;
				settled = true;
				if (timeoutId) clearTimeout(timeoutId);
				stdoutStream.end();
				stderrStream.end();
				resolve();
			};
			const rejectOnce = (error: Error) => {
				if (settled) return;
				settled = true;
				if (timeoutId) clearTimeout(timeoutId);
				stdoutStream.end();
				stderrStream.end();
				reject(error);
			};

			this.docker.modem.demuxStream(stream, stdoutStream, stderrStream);
			stream.on("end", resolveOnce);
			stream.on("error", (error) => rejectOnce(error instanceof Error ? error : new Error(String(error))));
			if (options?.timeoutMs) {
				timeoutId = setTimeout(() => {
					void (async () => {
						const stderrSoFar = Buffer.concat(stderrChunks).toString("utf-8");
						const { pid } = stripExecPidMarker(stderrSoFar);
						if (pid !== null) {
							await this.terminateExecProcess(container, pid).catch(() => {});
						}
						stream.destroy();
						rejectOnce(new Error(`Command timed out after ${options.timeoutMs}ms`));
					})();
				}, options.timeoutMs);
			}
		});

		const info = await exec.inspect();
		const stdout = Buffer.concat(stdoutChunks).toString("utf-8");
		const stderr = Buffer.concat(stderrChunks).toString("utf-8");
		const sanitizedStderr = stripExecPidMarker(stderr).stderr;
		return {
			stdout,
			stderr: sanitizedStderr,
			exitCode: info.ExitCode ?? -1,
		};
	}
}
