import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { SecurityScope } from "./scope.js";
import { isActionAllowed, isDomainAllowed, validateScope } from "./scope-validator.js";

// minimal valid scope helper
const baseScope: SecurityScope = {
	engagementId: "eng-001",
	mode: "blackbox",
	scanMode: "standard",
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
	metadata: { source: "cli", verified: true, createdAt: Date.now(), updatedAt: Date.now() },
};

describe("validateScope", () => {
	it("rejects scope with no targets", () => {
		const errors = validateScope({
			engagementId: "eng-001",
			mode: "blackbox",
			scanMode: "standard",
			executionMode: "read_only",
			targets: [],
			exclusions: [],
			allowedActions: ["read_files"],
			filesystem: {
				readableRoots: [],
				writableRoots: [],
				blockedPaths: [],
				artifactDir: "/tmp/run",
			},
			network: {
				allowedDomains: [],
				deniedDomains: [],
				allowedCidrs: [],
				deniedCidrs: [],
				browserEnabled: false,
				proxyEnabled: false,
			},
			reporting: { outputDir: "/tmp/reports", formats: ["markdown"] },
			metadata: { source: "cli", verified: true, createdAt: Date.now(), updatedAt: Date.now() },
		});
		assert.ok(errors.some((e) => e.includes("at least one target")));
	});

	it("accepts valid scope", () => {
		const errors = validateScope({
			engagementId: "eng-001",
			mode: "blackbox",
			scanMode: "standard",
			executionMode: "read_only",
			targets: [
				{
					id: "t1",
					type: "web_application",
					value: "https://example.com",
					origins: ["https://example.com"],
				},
			],
			exclusions: [],
			allowedActions: ["read_files", "http_test"],
			filesystem: {
				readableRoots: [],
				writableRoots: [],
				blockedPaths: [],
				artifactDir: "/tmp/run",
			},
			network: {
				allowedDomains: ["example.com"],
				deniedDomains: [],
				allowedCidrs: [],
				deniedCidrs: [],
				browserEnabled: false,
				proxyEnabled: false,
			},
			reporting: { outputDir: "/tmp/reports", formats: ["markdown"] },
			metadata: { source: "cli", verified: true, createdAt: Date.now(), updatedAt: Date.now() },
		});
		assert.deepStrictEqual(errors, []);
	});
});

describe("isActionAllowed", () => {
	it("returns true for allowed action", () => {
		assert.ok(isActionAllowed(baseScope, "read_files"));
	});
	it("returns false for disallowed action", () => {
		assert.ok(!isActionAllowed(baseScope, "modify_code"));
	});
});

describe("isDomainAllowed", () => {
	it("allows domain in allowedDomains", () => {
		assert.ok(isDomainAllowed(baseScope, "example.com"));
	});
	it("allows subdomain of allowedDomains", () => {
		assert.ok(isDomainAllowed(baseScope, "api.example.com"));
	});
	it("blocks domain in deniedDomains", () => {
		assert.ok(!isDomainAllowed(baseScope, "evil.com"));
	});
	it("blocks empty string domain", () => {
		assert.ok(!isDomainAllowed(baseScope, ""));
	});
});
