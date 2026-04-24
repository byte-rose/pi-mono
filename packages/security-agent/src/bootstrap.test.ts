// packages/security-agent/src/bootstrap.test.ts
import assert from "node:assert/strict";
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
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

describe("createSecuritySession", () => {
	afterEach(async () => {
		await rm(TEST_RUN_DIR, { recursive: true, force: true });
	});

	it("creates session with 10 tools and store", async () => {
		const session = await createSecuritySession({ scope, runDir: TEST_RUN_DIR, useSandbox: false });
		assert.ok(session.context.store);
		assert.strictEqual(session.tools.length, 10);
		assert.ok(typeof session.systemPrompt === "string");
		assert.ok(session.systemPrompt.includes("test-eng-001"));
		assert.ok(session.systemPrompt.length > 100);
		// reporting tools
		assert.ok(session.tools.some((t) => t.name === "create_finding"));
		assert.ok(session.tools.some((t) => t.name === "list_findings"));
		assert.ok(session.tools.some((t) => t.name === "attach_evidence"));
		assert.ok(session.tools.some((t) => t.name === "export_report"));
		// runtime tools
		assert.ok(session.tools.some((t) => t.name === "terminal_exec"));
		assert.ok(session.tools.some((t) => t.name === "get_scope"));
		// browser tools
		assert.ok(session.tools.some((t) => t.name === "browser_action"));
		// scanner tools
		assert.ok(session.tools.some((t) => t.name === "nuclei_scan"));
		assert.ok(session.tools.some((t) => t.name === "semgrep_scan"));
		assert.ok(session.tools.some((t) => t.name === "httpx_probe"));
		await session.cleanup();
	});

	it("rejects invalid scope", async () => {
		await assert.rejects(
			() => createSecuritySession({ scope: { ...scope, targets: [] }, runDir: TEST_RUN_DIR }),
			/Invalid scope/,
		);
	});
});
