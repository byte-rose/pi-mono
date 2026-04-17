import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { Evidence, Finding } from "@byte-rose/nyati-security-artifacts";
import { renderEvidenceMd, renderFindingMd, renderFindingsTableMd } from "./renderers.js";

const finding: Finding = {
	id: "f1",
	title: "Reflected XSS in search parameter",
	category: "XSS",
	severity: "high",
	confidence: "high",
	status: "validated",
	targets: ["https://example.com"],
	evidenceIds: [],
	cwe: "CWE-79",
	summary: "User-supplied input reflected in search results without encoding.",
	technicalAnalysis: "The `q` parameter is reflected in the HTML body without sanitization.",
	impact: "Session hijacking and credential theft.",
	remediation: "HTML-encode all user-supplied output.",
	createdAt: 0,
	updatedAt: 0,
};

const evidence: Evidence = {
	id: "e1",
	findingId: "f1",
	type: "http",
	title: "XSS Proof-of-Concept Request",
	content: "GET /search?q=<script>alert(1)</script> HTTP/1.1\nHost: example.com",
	targets: ["https://example.com"],
	createdAt: 0,
};

describe("renderFindingMd", () => {
	it("includes the finding title as heading", () => {
		const md = renderFindingMd(finding);
		assert.ok(md.includes("# Reflected XSS in search parameter"));
	});

	it("includes severity, confidence, and status", () => {
		const md = renderFindingMd(finding);
		assert.ok(md.includes("high"));
		assert.ok(md.includes("validated"));
	});

	it("includes CWE when present", () => {
		const md = renderFindingMd(finding);
		assert.ok(md.includes("CWE-79"));
	});

	it("includes all four prose sections", () => {
		const md = renderFindingMd(finding);
		assert.ok(md.includes("## Summary"));
		assert.ok(md.includes("## Technical Analysis"));
		assert.ok(md.includes("## Impact"));
		assert.ok(md.includes("## Remediation"));
	});

	it("includes finding summary text", () => {
		const md = renderFindingMd(finding);
		assert.ok(md.includes("reflected in search results"));
	});

	it("omits CVE line when cve is absent", () => {
		const md = renderFindingMd(finding);
		assert.ok(!md.includes("**CVE:**"));
	});

	it("includes CVSS score when present", () => {
		const withCvss = { ...finding, cvssScore: 8.1 };
		const md = renderFindingMd(withCvss);
		assert.ok(md.includes("8.1"));
	});
});

describe("renderFindingsTableMd", () => {
	it("returns placeholder for empty array", () => {
		assert.strictEqual(renderFindingsTableMd([]), "_No findings._");
	});

	it("includes table header row", () => {
		const md = renderFindingsTableMd([finding]);
		assert.ok(md.includes("| Severity | Title | Category | Status |"));
	});

	it("includes finding row with correct values", () => {
		const md = renderFindingsTableMd([finding]);
		assert.ok(md.includes("high"));
		assert.ok(md.includes("Reflected XSS in search parameter"));
		assert.ok(md.includes("XSS"));
		assert.ok(md.includes("validated"));
	});

	it("renders multiple findings as multiple rows", () => {
		const second = { ...finding, id: "f2", title: "SQL Injection in login" };
		const md = renderFindingsTableMd([finding, second]);
		assert.ok(md.includes("SQL Injection in login"));
		const rows = md.split("\n").filter((l) => l.startsWith("|") && !l.includes("---"));
		assert.strictEqual(rows.length, 3); // header + 2 data rows
	});
});

describe("renderEvidenceMd", () => {
	it("includes the evidence title as heading", () => {
		const md = renderEvidenceMd(evidence);
		assert.ok(md.includes("## XSS Proof-of-Concept Request"));
	});

	it("includes the evidence type", () => {
		const md = renderEvidenceMd(evidence);
		assert.ok(md.includes("http"));
	});

	it("includes content in a code block for string content", () => {
		const md = renderEvidenceMd(evidence);
		assert.ok(md.includes("```"));
		assert.ok(md.includes("GET /search"));
	});

	it("renders object content as JSON code block", () => {
		const jsonEvidence = { ...evidence, content: { status: 200, body: "ok" } };
		const md = renderEvidenceMd(jsonEvidence);
		assert.ok(md.includes("```json"));
		assert.ok(md.includes('"status"'));
	});
});
