import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { SecurityScope } from "./scope.js";
import { buildSecuritySystemPrompt } from "./system-prompt.js";

const scope: SecurityScope = {
	engagementId: "eng-test-001",
	mode: "blackbox",
	scanMode: "quick",
	executionMode: "read_only",
	targets: [{ id: "t1", type: "web_application", value: "https://example.com", origins: ["https://example.com"] }],
	exclusions: [],
	allowedActions: ["http_test", "create_reports"],
	filesystem: { readableRoots: [], writableRoots: [], blockedPaths: [], artifactDir: "/tmp/artifacts" },
	network: {
		allowedDomains: ["example.com"],
		deniedDomains: [],
		allowedCidrs: [],
		deniedCidrs: [],
		browserEnabled: false,
		proxyEnabled: false,
	},
	reporting: { outputDir: "/tmp/reports", formats: ["markdown"] },
	metadata: { source: "cli", verified: true, createdAt: 0, updatedAt: 0 },
};

describe("buildSecuritySystemPrompt", () => {
	it("contains the engagement ID", () => {
		const prompt = buildSecuritySystemPrompt(scope);
		assert.ok(prompt.includes("eng-test-001"));
	});

	it("contains mode, scanMode, and executionMode", () => {
		const prompt = buildSecuritySystemPrompt(scope);
		assert.ok(prompt.includes("blackbox"));
		assert.ok(prompt.includes("quick"));
		assert.ok(prompt.includes("read_only"));
	});

	it("contains the target URL", () => {
		const prompt = buildSecuritySystemPrompt(scope);
		assert.ok(prompt.includes("https://example.com"));
	});

	it("lists allowed actions", () => {
		const prompt = buildSecuritySystemPrompt(scope);
		assert.ok(prompt.includes("http_test"));
		assert.ok(prompt.includes("create_reports"));
	});

	it("contains current date", () => {
		const prompt = buildSecuritySystemPrompt(scope);
		const today = new Date().toISOString().slice(0, 10);
		assert.ok(prompt.includes(today));
	});

	it("appends skillsSection when provided", () => {
		const prompt = buildSecuritySystemPrompt(scope, "\n\n# Skills\n\n## xss\n\nXSS content.");
		assert.ok(prompt.includes("# Skills"));
		assert.ok(prompt.includes("XSS content."));
	});

	it("returns a non-empty string without skillsSection", () => {
		const prompt = buildSecuritySystemPrompt(scope);
		assert.ok(prompt.length > 100);
	});
});
