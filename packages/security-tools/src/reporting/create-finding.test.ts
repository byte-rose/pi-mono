// packages/security-tools/src/reporting/create-finding.test.ts

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { ArtifactStore } from "@byte-rose/nyati-security-artifacts";
import type { SecurityScope } from "../scope.js";
import { createFindingTool } from "./create-finding.js";

const scope: SecurityScope = {
	engagementId: "eng-finding-001",
	mode: "blackbox",
	scanMode: "standard",
	executionMode: "validate",
	targets: [{ id: "t1", type: "web_application", value: "https://example.com", origins: ["https://example.com"] }],
	exclusions: [],
	allowedActions: ["create_reports"],
	filesystem: { readableRoots: [], writableRoots: [], blockedPaths: [], artifactDir: "/tmp/run" },
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

const baseFinding = {
	title: "Reflected XSS",
	category: "xss",
	summary: "Search reflects input.",
	technicalAnalysis: "The search endpoint reflects q without output encoding.",
	impact: "An attacker can run JavaScript in a victim browser.",
	remediation: "HTML encode reflected values.",
};

describe("createFindingTool scope validation", () => {
	let tmpDir: string;

	before(async () => {
		tmpDir = await mkdtemp(join(tmpdir(), "nyati-create-finding-"));
	});

	after(async () => {
		await rm(tmpDir, { recursive: true, force: true });
	});

	it("rejects finding targets outside active scope", async () => {
		const tool = createFindingTool(new ArtifactStore(tmpDir), scope);

		const result = await tool.execute({
			...baseFinding,
			targets: ["https://outside.example.net"],
		});

		assert.strictEqual(result.success, false);
		assert.match(String(result.error), /outside scope/i);
	});

	it("accepts target ids and scoped endpoints", async () => {
		const tool = createFindingTool(new ArtifactStore(tmpDir), scope);

		const result = await tool.execute({
			...baseFinding,
			targets: ["t1"],
			endpoint: "https://example.com/search",
		});

		assert.strictEqual(result.success, true);
		assert.ok(result.findingId);
	});
});
