// packages/security-agent/src/bootstrap.test.ts
import assert from "node:assert/strict";
import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import type {
	CreateWorkspaceInput,
	ExecOptions,
	ExecResult,
	SecurityRuntime,
	WorkspaceHandle,
} from "@byte-rose/nyati-security-runtime";
import { createSecuritySession } from "./bootstrap.js";
import type { SecurityScope } from "./scope.js";

const TEST_RUN_DIR = join(tmpdir(), `nyati-bootstrap-test-${Date.now()}`);

const scope: SecurityScope = {
	engagementId: "test-eng-001",
	mode: "blackbox",
	scanMode: "quick",
	executionMode: "read_only",
	targets: [{ id: "t1", type: "web_application", value: "https://example.com", origins: ["https://example.com"] }],
	exclusions: [],
	allowedActions: ["read_files", "browser_test"],
	filesystem: { readableRoots: [], writableRoots: [], blockedPaths: [], artifactDir: TEST_RUN_DIR },
	network: {
		allowedDomains: ["example.com"],
		deniedDomains: [],
		allowedCidrs: [],
		deniedCidrs: [],
		browserEnabled: true,
		proxyEnabled: false,
	},
	reporting: { outputDir: join(TEST_RUN_DIR, "reports"), formats: ["markdown"] },
	metadata: { source: "cli", verified: true, createdAt: Date.now(), updatedAt: Date.now() },
};

class FakeSecurityRuntime implements SecurityRuntime {
	readonly createWorkspaceCalls: CreateWorkspaceInput[] = [];
	readonly syncTargetsCalls: Array<{ workspaceId: string; targets: unknown[] }> = [];
	readonly destroyWorkspaceCalls: string[] = [];
	cleanupCalled = false;
	workspace: WorkspaceHandle = {
		workspaceId: "ws-test-001",
		containerId: "container-test-001",
		workspacePath: "/workspace",
	};

	async createWorkspace(input: CreateWorkspaceInput): Promise<WorkspaceHandle> {
		this.createWorkspaceCalls.push(input);
		return this.workspace;
	}

	async destroyWorkspace(workspaceId: string): Promise<void> {
		this.destroyWorkspaceCalls.push(workspaceId);
	}

	async syncTargets(workspaceId: string, targets: unknown[]): Promise<void> {
		this.syncTargetsCalls.push({ workspaceId, targets });
	}

	async execInContainer(_workspaceId: string, _command: string, _options?: ExecOptions): Promise<ExecResult> {
		return { stdout: "", stderr: "", exitCode: 0 };
	}

	cleanup(): void {
		this.cleanupCalled = true;
	}
}

describe("createSecuritySession", () => {
	afterEach(async () => {
		await rm(TEST_RUN_DIR, { recursive: true, force: true });
	});

	it("creates a no-sandbox session without sandbox-only tools", async () => {
		const session = await createSecuritySession({ scope, runDir: TEST_RUN_DIR, useSandbox: false });
		assert.ok(session.context.store);
		assert.strictEqual(session.tools.length, 8);
		assert.ok(typeof session.systemPrompt === "string");
		assert.ok(session.systemPrompt.includes("test-eng-001"));
		assert.ok(session.systemPrompt.length > 100);
		assert.ok(session.tools.some((tool) => tool.name === "create_finding"));
		assert.ok(session.tools.some((tool) => tool.name === "list_findings"));
		assert.ok(session.tools.some((tool) => tool.name === "attach_evidence"));
		assert.ok(session.tools.some((tool) => tool.name === "export_report"));
		assert.ok(session.tools.some((tool) => tool.name === "get_scope"));
		assert.ok(session.tools.some((tool) => tool.name === "add_scope_target"));
		assert.ok(session.tools.some((tool) => tool.name === "browser_action"));
		assert.ok(session.tools.some((tool) => tool.name === "http_request"));
		assert.ok(!session.tools.some((tool) => tool.name === "terminal_exec"));
		assert.ok(!session.tools.some((tool) => tool.name === "nuclei_scan"));
		assert.ok(!session.tools.some((tool) => tool.name === "semgrep_scan"));
		assert.ok(!session.tools.some((tool) => tool.name === "httpx_probe"));
		await session.cleanup();
	});

	it("rebuilds the system prompt from expanded scope", async () => {
		const session = await createSecuritySession({
			scope: structuredClone(scope),
			runDir: TEST_RUN_DIR,
			useSandbox: false,
		});
		const addTarget = session.tools.find((tool) => tool.name === "add_scope_target");
		assert.ok(addTarget);

		await addTarget.execute({ url: "https://new.example.com" });

		assert.ok(session.buildSystemPrompt().includes("https://new.example.com/"));
		const scopeJson = JSON.parse(await readFile(join(TEST_RUN_DIR, "scope.json"), "utf-8")) as SecurityScope;
		assert.ok(scopeJson.targets.some((target) => target.value === "https://new.example.com/"));
		const scopeEvents = await readFile(join(TEST_RUN_DIR, "scope-events.jsonl"), "utf-8");
		assert.match(scopeEvents, /target_added/);
		await session.cleanup();
	});

	it("enforces allowedActions before tool execution", async () => {
		const session = await createSecuritySession({ scope, runDir: TEST_RUN_DIR, useSandbox: false });
		const createFinding = session.tools.find((tool) => tool.name === "create_finding") as
			| {
					execute(input: {
						title: string;
						category: string;
						summary: string;
						technicalAnalysis: string;
						impact: string;
						remediation: string;
					}): Promise<{ success: boolean; error?: unknown }>;
			  }
			| undefined;
		const httpRequest = session.tools.find((tool) => tool.name === "http_request") as
			| { execute(input: { url: string }): Promise<{ success: boolean; error?: unknown }> }
			| undefined;
		const getScope = session.tools.find((tool) => tool.name === "get_scope") as
			| { execute(input: Record<string, never>): Promise<{ success: boolean }> }
			| undefined;
		assert.ok(createFinding);
		assert.ok(httpRequest);
		assert.ok(getScope);

		const findingResult = await createFinding.execute({
			title: "Blocked finding",
			category: "xss",
			summary: "summary",
			technicalAnalysis: "analysis",
			impact: "impact",
			remediation: "remediation",
		});
		assert.strictEqual(findingResult.success, false);
		assert.match(String(findingResult.error), /create_reports/);

		const requestResult = await httpRequest.execute({ url: "https://example.com" });
		assert.strictEqual(requestResult.success, false);
		assert.match(String(requestResult.error), /http_test/);

		const scopeResult = await getScope.execute({});
		assert.strictEqual(scopeResult.success, true);
		await session.cleanup();
	});

	it("syncs targets into sandbox and uses minimal caps for non-network scans", async () => {
		const runtime = new FakeSecurityRuntime();
		const session = await createSecuritySession({
			scope: { ...scope, allowedActions: [...scope.allowedActions, "run_commands"] },
			runDir: TEST_RUN_DIR,
			useSandbox: true,
			runtime,
		});
		assert.deepStrictEqual(runtime.createWorkspaceCalls, [{ agentId: "test-eng-001", capAdd: [] }]);
		assert.deepStrictEqual(runtime.syncTargetsCalls, [{ workspaceId: "ws-test-001", targets: scope.targets }]);
		assert.deepStrictEqual(session.context.workspace, runtime.workspace);
		await session.cleanup();
		assert.deepStrictEqual(runtime.destroyWorkspaceCalls, ["ws-test-001"]);
		assert.strictEqual(runtime.cleanupCalled, true);
	});

	it("adds NET_RAW when network scans are allowed", async () => {
		const runtime = new FakeSecurityRuntime();
		const session = await createSecuritySession({
			scope: { ...scope, allowedActions: [...scope.allowedActions, "run_commands", "network_scan"] },
			runDir: TEST_RUN_DIR,
			useSandbox: true,
			runtime,
		});
		assert.deepStrictEqual(runtime.createWorkspaceCalls, [{ agentId: "test-eng-001", capAdd: ["NET_RAW"] }]);
		await session.cleanup();
	});

	it("rejects invalid scope", async () => {
		await assert.rejects(
			() => createSecuritySession({ scope: { ...scope, targets: [] }, runDir: TEST_RUN_DIR }),
			/Invalid scope/,
		);
	});
});
