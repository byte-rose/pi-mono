// packages/security-tools/src/runtime/terminal-exec.test.ts
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { terminalExecTool } from "./terminal-exec.js";

describe("terminalExecTool", () => {
	it("returns error when exec is null", async () => {
		const tool = terminalExecTool(null, undefined);
		const result = await tool.execute({ command: "ls" });
		assert.strictEqual(result.success, false);
		assert.ok((result.error as string).includes("No sandbox"));
	});

	it("returns error when workspace is undefined", async () => {
		const fakeExec = async () => ({ stdout: "", stderr: "", exitCode: 0 });
		const tool = terminalExecTool(fakeExec, undefined);
		const result = await tool.execute({ command: "ls" });
		assert.strictEqual(result.success, false);
		assert.ok((result.error as string).includes("No sandbox"));
	});

	it("calls exec and returns stdout/stderr/exitCode on success", async () => {
		const calls: Array<{ workspaceId: string; command: string }> = [];
		const fakeExec = async (workspaceId: string, command: string) => {
			calls.push({ workspaceId, command });
			return { stdout: "hello\n", stderr: "", exitCode: 0 };
		};
		const workspace = { workspaceId: "ws-123", containerId: "c-123", workspacePath: "/workspace" };
		const tool = terminalExecTool(fakeExec, workspace);
		const result = await tool.execute({ command: "echo hello" });
		assert.strictEqual(result.success, true);
		assert.strictEqual(result.stdout, "hello\n");
		assert.strictEqual(result.exitCode, 0);
		assert.strictEqual(calls.length, 1);
		assert.strictEqual(calls[0].workspaceId, "ws-123");
		assert.strictEqual(calls[0].command, "echo hello");
	});

	it("returns success:false when exitCode is non-zero", async () => {
		const fakeExec = async () => ({ stdout: "", stderr: "not found\n", exitCode: 127 });
		const workspace = { workspaceId: "ws-1", containerId: "c-1", workspacePath: "/workspace" };
		const tool = terminalExecTool(fakeExec, workspace);
		const result = await tool.execute({ command: "bogus" });
		assert.strictEqual(result.success, false);
		assert.strictEqual(result.exitCode, 127);
	});

	it("has correct tool metadata", () => {
		const tool = terminalExecTool(null, undefined);
		assert.strictEqual(tool.name, "terminal_exec");
		assert.ok(tool.description.length > 0);
	});
});
