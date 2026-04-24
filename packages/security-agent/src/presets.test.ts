import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { deepWhiteboxAudit, quickBlackboxWebScan, standardBlackboxWebScan } from "./presets.js";
import { validateScope } from "./scope-validator.js";

describe("quickBlackboxWebScan", () => {
	it("produces a valid scope", () => {
		const scope = quickBlackboxWebScan("https://example.com", "eng-001");
		assert.deepStrictEqual(validateScope(scope), []);
	});

	it("sets scanMode to quick and mode to blackbox", () => {
		const scope = quickBlackboxWebScan("https://example.com", "eng-001");
		assert.strictEqual(scope.scanMode, "quick");
		assert.strictEqual(scope.mode, "blackbox");
		assert.strictEqual(scope.executionMode, "read_only");
	});

	it("sets target hostname as allowed domain", () => {
		const scope = quickBlackboxWebScan("https://example.com/path", "eng-001");
		assert.ok(scope.network.allowedDomains.includes("example.com"));
	});

	it("uses engagementId in artifactDir and outputDir", () => {
		const scope = quickBlackboxWebScan("https://example.com", "eng-xyz");
		assert.ok(scope.filesystem.artifactDir.includes("eng-xyz"));
		assert.ok(scope.reporting.outputDir.includes("eng-xyz"));
	});

	it("enables browser workflows by default", () => {
		const scope = quickBlackboxWebScan("https://example.com", "eng-001");
		assert.ok(scope.network.browserEnabled);
		assert.ok(scope.allowedActions.includes("browser_test"));
	});
});

describe("standardBlackboxWebScan", () => {
	it("produces a valid scope", () => {
		const scope = standardBlackboxWebScan("https://example.com", "eng-002");
		assert.deepStrictEqual(validateScope(scope), []);
	});

	it("sets scanMode to standard and executionMode to validate", () => {
		const scope = standardBlackboxWebScan("https://example.com", "eng-002");
		assert.strictEqual(scope.scanMode, "standard");
		assert.strictEqual(scope.executionMode, "validate");
	});

	it("enables browser workflows by default", () => {
		const scope = standardBlackboxWebScan("https://example.com", "eng-002");
		assert.ok(scope.network.browserEnabled);
		assert.ok(scope.allowedActions.includes("browser_test"));
	});
});

describe("deepWhiteboxAudit", () => {
	it("produces a valid scope", () => {
		const scope = deepWhiteboxAudit("https://example.com", "eng-003", "/workspace/app");
		assert.deepStrictEqual(validateScope(scope), []);
	});

	it("sets mode to whitebox, scanMode to deep, executionMode to exploit", () => {
		const scope = deepWhiteboxAudit("https://example.com", "eng-003", "/workspace/app");
		assert.strictEqual(scope.mode, "whitebox");
		assert.strictEqual(scope.scanMode, "deep");
		assert.strictEqual(scope.executionMode, "exploit");
	});

	it("includes both web_application and local_code targets", () => {
		const scope = deepWhiteboxAudit("https://example.com", "eng-003", "/workspace/app");
		assert.ok(scope.targets.some((t) => t.type === "web_application"));
		assert.ok(scope.targets.some((t) => t.type === "local_code"));
	});

	it("sets workspacePath in filesystem.readableRoots", () => {
		const scope = deepWhiteboxAudit("https://example.com", "eng-003", "/workspace/app");
		assert.ok(scope.filesystem.readableRoots.includes("/workspace/app"));
	});
});
