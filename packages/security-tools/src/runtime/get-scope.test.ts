// packages/security-tools/src/runtime/get-scope.test.ts
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { SecurityScope } from "../scope.js";
import { getScopeTool } from "./get-scope.js";

const scope: SecurityScope = {
	engagementId: "eng-test-001",
	mode: "blackbox",
	scanMode: "quick",
	executionMode: "read_only",
	targets: [{ id: "t1", type: "web_application", value: "https://example.com", origins: ["https://example.com"] }],
	exclusions: [],
	allowedActions: ["read_files", "http_test"],
	filesystem: { readableRoots: [], writableRoots: [], blockedPaths: [], artifactDir: "/tmp/run" },
	network: {
		allowedDomains: ["example.com"],
		deniedDomains: ["evil.com"],
		allowedCidrs: [],
		deniedCidrs: [],
		browserEnabled: false,
		proxyEnabled: false,
	},
	reporting: { outputDir: "/tmp/reports", formats: ["markdown"] },
	metadata: { source: "cli", verified: true, createdAt: 0, updatedAt: 0 },
};

describe("getScopeTool", () => {
	it("has correct tool metadata", () => {
		const tool = getScopeTool(scope);
		assert.strictEqual(tool.name, "get_scope");
		assert.ok(tool.description.length > 0);
	});

	it("returns scope fields on execute", async () => {
		const tool = getScopeTool(scope);
		const result = await tool.execute({});
		assert.strictEqual(result.success, true);
		assert.strictEqual(result.engagementId, "eng-test-001");
		assert.strictEqual(result.mode, "blackbox");
		assert.strictEqual(result.scanMode, "quick");
		assert.strictEqual(result.executionMode, "read_only");
		assert.deepStrictEqual(result.allowedActions, ["read_files", "http_test"]);
	});

	it("returns targets array", async () => {
		const tool = getScopeTool(scope);
		const result = await tool.execute({});
		assert.ok(Array.isArray(result.targets));
		assert.strictEqual((result.targets as unknown[]).length, 1);
	});

	it("returns network and filesystem policies", async () => {
		const tool = getScopeTool(scope);
		const result = await tool.execute({});
		assert.ok(result.network);
		assert.ok(result.filesystem);
	});
});
