import assert from "node:assert/strict";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { ArtifactStore } from "./store.js";

describe("ArtifactStore", () => {
	let tmpDir: string;

	before(async () => {
		tmpDir = await mkdtemp(join(tmpdir(), "nyati-store-test-"));
	});

	after(async () => {
		await rm(tmpDir, { recursive: true, force: true });
	});

	it("stores and retrieves a finding", async () => {
		const store = new ArtifactStore(tmpDir);
		const id = await store.appendFinding({
			title: "SQL Injection",
			severity: "high",
			status: "candidate",
			category: "injection",
			confidence: "high",
			targets: ["https://example.com"],
			evidenceIds: [],
			summary: "Unparameterised query in login endpoint",
			technicalAnalysis: "User input directly concatenated into SQL",
			impact: "Full database read/write access",
			remediation: "Use prepared statements",
		});
		assert.ok(id, "should return an ID");
		const findings = await store.listFindings();
		assert.equal(findings.length, 1);
		assert.equal(findings[0]!.id, id);
		assert.equal(findings[0]!.title, "SQL Injection");
	});

	it("persists findings across store instances (JSONL replay)", async () => {
		const dir = await mkdtemp(join(tmpdir(), "nyati-replay-test-"));
		try {
			const store1 = new ArtifactStore(dir);
			await store1.appendFinding({
				title: "SSRF",
				severity: "critical",
				status: "validated",
				category: "ssrf",
				confidence: "high",
				targets: [],
				evidenceIds: [],
				summary: "Internal metadata fetch via user-controlled URL",
				technicalAnalysis: "No SSRF protection on URL parameter",
				impact: "Cloud credential theft via IMDS",
				remediation: "Block internal IP ranges at application layer",
			});
			// New store instance — must replay from JSONL
			const store2 = new ArtifactStore(dir);
			const findings = await store2.listFindings();
			assert.equal(findings.length, 1);
			assert.equal(findings[0]!.title, "SSRF");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("stores and retrieves evidence", async () => {
		const store = new ArtifactStore(tmpDir);
		const fId = await store.appendFinding({
			title: "XSS",
			severity: "medium",
			status: "candidate",
			category: "xss",
			confidence: "medium",
			targets: [],
			evidenceIds: [],
			summary: "Reflected XSS",
			technicalAnalysis: "Search param reflected unencoded",
			impact: "Session hijacking",
			remediation: "HTML encode output",
		});
		const eId = await store.appendEvidence({
			findingId: fId,
			type: "http",
			title: "PoC HTTP exchange",
			content: "GET /?q=<script>alert(1)</script>",
			targets: [],
		});
		const evidence = await store.listEvidence(fId);
		assert.equal(evidence.length, 1);
		assert.equal(evidence[0]!.id, eId);
		assert.equal(evidence[0]!.findingId, fId);
	});

	it("updateFinding patches without overwriting other fields", async () => {
		const store = new ArtifactStore(tmpDir);
		const id = await store.appendFinding({
			title: "IDOR",
			severity: "high",
			status: "candidate",
			category: "idor",
			confidence: "medium",
			targets: [],
			evidenceIds: [],
			summary: "IDOR on /api/users/:id",
			technicalAnalysis: "No ownership check",
			impact: "PII exposure",
			remediation: "Verify ownership server-side",
		});
		await store.updateFinding(id, { status: "validated" });
		const f = await store.getFinding(id);
		assert.equal(f!.status, "validated");
		assert.equal(f!.title, "IDOR"); // unchanged
	});
});
