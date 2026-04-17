// packages/security-tools/src/runtime/terminal-exec.ts
import { type Static, Type } from "@sinclair/typebox";
import type { ExecFn, SecurityTool, WorkspaceHandle } from "../types.js";

const terminalExecSchema = Type.Object({
	command: Type.String({ description: "Shell command to run in the sandbox container" }),
	workingDir: Type.Optional(Type.String({ description: "Working directory inside container. Default: /workspace" })),
	timeoutSeconds: Type.Optional(Type.Number({ description: "Timeout in seconds. Default: 30" })),
});

type TerminalExecInput = Static<typeof terminalExecSchema>;

export function terminalExecTool(
	exec: ExecFn | null,
	workspace: WorkspaceHandle | undefined,
): SecurityTool<TerminalExecInput> {
	return {
		name: "terminal_exec",
		label: "Terminal Exec",
		description:
			"Run a shell command inside the sandboxed Docker container. " +
			"Use for file enumeration, running installed security tools, or any command-line operation. " +
			"Returns stdout, stderr, and exit code.",
		parameters: terminalExecSchema,
		async execute(input) {
			if (!exec || !workspace) {
				return { success: false, error: "No sandbox available. Start session with useSandbox: true." };
			}
			const timeoutMs = (input.timeoutSeconds ?? 30) * 1000;
			const result = await exec(workspace.workspaceId, input.command, {
				workingDir: input.workingDir,
				timeoutMs,
			});
			return {
				success: result.exitCode === 0,
				stdout: result.stdout,
				stderr: result.stderr,
				exitCode: result.exitCode,
			};
		},
	};
}
