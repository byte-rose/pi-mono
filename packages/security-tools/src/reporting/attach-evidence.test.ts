// packages/security-tools/src/reporting/attach-evidence.test.ts

import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { ArtifactStore } from "@byte-rose/nyati-security-artifacts";
import type { SecurityScope } from "../scope.js";
import { attachEvidenceTool } from "./attach-evidence.js";

const scope: SecurityScope = {
	engagementId: "eng-evidence-001",
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

describe("attachEvidenceTool scope validation", () => {
	let tmpDir: string;

	before(async () => {
		tmpDir = await mkdtemp(join(tmpdir(), "nyati-attach-evidence-"));
	});

	after(async () => {
		await rm(tmpDir, { recursive: true, force: true });
	});

	async function createStoreWithFinding(): Promise<{ store: ArtifactStore; findingId: string }> {
		const store = new ArtifactStore(tmpDir);
		const findingId = await store.appendFinding({
			title: "Reflected XSS",
			category: "xss",
			severity: "medium",
			confidence: "medium",
			status: "candidate",
			targets: ["t1"],
			evidenceIds: [],
			summary: "Search reflects input.",
			technicalAnalysis: "The search endpoint reflects q without output encoding.",
			impact: "An attacker can run JavaScript in a victim browser.",
			remediation: "HTML encode reflected values.",
		});
		return { store, findingId };
	}

	it("rejects evidence targets outside active scope", async () => {
		const { store, findingId } = await createStoreWithFinding();
		const tool = attachEvidenceTool(store, scope);

		const result = await tool.execute({
			findingId,
			title: "PoC",
			type: "http",
			content: "GET / HTTP/1.1",
			targets: ["https://outside.example.net"],
		});

		assert.strictEqual(result.success, false);
		assert.match(String(result.error), /outside scope/i);
	});

	it("attaches scoped evidence and preserves string content without metadata", async () => {
		const { store, findingId } = await createStoreWithFinding();
		const tool = attachEvidenceTool(store, scope);

		const result = await tool.execute({
			findingId,
			title: "PoC",
			type: "http",
			content: "GET / HTTP/1.1",
			targets: ["https://example.com"],
		});

		assert.strictEqual(result.success, true);
		const evidence = await store.listEvidence(findingId);
		assert.strictEqual(evidence.at(-1)?.content, "GET / HTTP/1.1");
	});
});
