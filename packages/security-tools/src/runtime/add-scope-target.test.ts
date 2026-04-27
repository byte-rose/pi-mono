// packages/security-tools/src/runtime/add-scope-target.test.ts

import assert from "node:assert/strict";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, it } from "node:test";
import { browserActionTool } from "../browser/browser-action.js";
import type { SecurityScope } from "../scope.js";
import { addScopeTargetTool } from "./add-scope-target.js";

function createScope(): SecurityScope {
	return {
		engagementId: "eng-expand-001",
		mode: "blackbox",
		scanMode: "standard",
		executionMode: "validate",
		targets: [{ id: "t1", type: "web_application", value: "https://example.com", origins: ["https://example.com"] }],
		exclusions: [],
		allowedActions: ["browser_test", "create_reports"],
		filesystem: { readableRoots: [], writableRoots: [], blockedPaths: [], artifactDir: "/tmp/run" },
		network: {
			allowedDomains: ["example.com"],
			deniedDomains: ["blocked.example.com"],
			allowedCidrs: [],
			deniedCidrs: [],
			browserEnabled: true,
			proxyEnabled: false,
		},
		reporting: { outputDir: "/tmp/reports", formats: ["markdown"] },
		metadata: { source: "cli", verified: true, createdAt: 0, updatedAt: 0 },
	};
}

describe("addScopeTargetTool", () => {
	it("adds a web target and expands allowed domains", async () => {
		const scope = createScope();
		const tool = addScopeTargetTool(scope);

		const result = await tool.execute({ url: "https://api.example.net/app" });

		assert.strictEqual(result.success, true);
		assert.strictEqual(result.added, true);
		assert.strictEqual(scope.targets.length, 2);
		assert.strictEqual(scope.targets[1]?.id, "t2");
		assert.strictEqual(scope.targets[1]?.type, "web_application");
		assert.strictEqual(scope.targets[1]?.value, "https://api.example.net/app");
		assert.deepStrictEqual(scope.targets[1]?.type === "web_application" ? scope.targets[1].origins : [], [
			"https://api.example.net",
		]);
		assert.strictEqual(scope.targets[1]?.status, "active");
		assert.strictEqual(scope.targets[1]?.provenance?.addedBy, "agent");
		assert.ok(scope.network.allowedDomains.includes("api.example.net"));
		assert.strictEqual(scope.metadata.verified, false);
		assert.ok(scope.metadata.updatedAt > 0);
	});

	it("passes mutation events to the audit hook", async () => {
		const scope = createScope();
		const events: unknown[] = [];
		const tool = addScopeTargetTool(scope, {
			onScopeChanged: async (event) => {
				events.push(event);
			},
		});

		await tool.execute({
			url: "https://api.example.net/app",
			discoveredFrom: "https://example.com/app",
			reason: "same engagement app",
		});

		assert.strictEqual(events.length, 1);
		assert.deepStrictEqual(events[0], {
			type: "target_added",
			timestamp: scope.metadata.updatedAt,
			target: scope.targets[1],
			targetCount: 2,
			allowedDomains: scope.network.allowedDomains,
			discoveredFrom: "https://example.com/app",
			reason: "same engagement app",
		});
	});

	it("keeps browser actions scoped to the expanded target set", async () => {
		const scope = createScope();
		const addTarget = addScopeTargetTool(scope);
		await addTarget.execute({ url: "https://next.example.net" });

		const browser = browserActionTool(scope, join(tmpdir(), "nyati-expanded-scope-test"), {
			runCommand: async () => ({ stdout: "opened", stderr: "", exitCode: 0 }),
		});

		const result = await browser.execute({ action: "open", url: "https://next.example.net" });

		assert.strictEqual(result.success, true);
	});

	it("does not add duplicate web targets", async () => {
		const scope = createScope();
		const tool = addScopeTargetTool(scope);

		const result = await tool.execute({ url: "https://example.com/" });

		assert.strictEqual(result.success, true);
		assert.strictEqual(result.added, false);
		assert.strictEqual(scope.targets.length, 1);
	});

	it("rejects denied domains", async () => {
		const scope = createScope();
		const tool = addScopeTargetTool(scope);

		const result = await tool.execute({ url: "https://blocked.example.com" });

		assert.strictEqual(result.success, false);
		assert.match(String(result.error), /denied/i);
		assert.strictEqual(scope.targets.length, 1);
	});
});
