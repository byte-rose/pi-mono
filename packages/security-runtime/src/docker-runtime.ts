// packages/security-runtime/src/docker-runtime.ts
import { randomBytes } from "node:crypto";
import { PassThrough } from "node:stream";
import Dockerode from "dockerode";
import { SandboxInitializationError } from "./errors.js";
import type { CreateWorkspaceInput, ExecOptions, ExecResult, SecurityRuntime, WorkspaceHandle } from "./runtime.js";

const CONTAINER_WORKSPACE_PATH = "/workspace";
const DEFAULT_IMAGE = process.env.NYATI_SANDBOX_IMAGE ?? "nyati-sandbox:latest";

export class DockerSecurityRuntime implements SecurityRuntime {
	private docker: Dockerode;
	private containers = new Map<string, Dockerode.Container>();

	constructor(socketPath?: string) {
		this.docker = socketPath ? new Dockerode({ socketPath }) : new Dockerode();
	}

	async createWorkspace(input: CreateWorkspaceInput): Promise<WorkspaceHandle> {
		const { agentId, localSources = [], envVars = {} } = input;
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
			HostConfig: {
				CapAdd: ["NET_ADMIN", "NET_RAW"],
			},
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

	async syncTargets(_workspaceId: string, _targets: unknown[]): Promise<void> {
		// Phase 2: write target config into container for scope enforcement
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
			Cmd: ["sh", "-c", command],
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
			this.docker.modem.demuxStream(stream, stdoutStream, stderrStream);
			stream.on("end", () => {
				stdoutStream.end();
				stderrStream.end();
				resolve();
			});
			stream.on("error", reject);
			if (options?.timeoutMs) {
				setTimeout(() => reject(new Error(`Command timed out after ${options.timeoutMs}ms`)), options.timeoutMs);
			}
		});

		const info = await exec.inspect();
		return {
			stdout: Buffer.concat(stdoutChunks).toString("utf-8"),
			stderr: Buffer.concat(stderrChunks).toString("utf-8"),
			exitCode: info.ExitCode ?? -1,
		};
	}
}
