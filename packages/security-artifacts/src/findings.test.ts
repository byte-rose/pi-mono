import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { findDuplicate, normalizeCve, normalizeCwe, validateFinding } from "./findings.js";

describe("validateFinding", () => {
	it("rejects empty title", () => {
		const errors = validateFinding({
			title: "",
			summary: "s",
			technicalAnalysis: "t",
			impact: "i",
			remediation: "r",
		});
		assert.ok(errors.includes("title cannot be empty"));
	});

	it("rejects empty summary", () => {
		const errors = validateFinding({
			title: "XSS",
			summary: "  ",
			technicalAnalysis: "t",
			impact: "i",
			remediation: "r",
		});
		assert.ok(errors.includes("summary cannot be empty"));
	});

	it("accepts all valid fields", () => {
		const errors = validateFinding({
			title: "XSS",
			summary: "s",
			technicalAnalysis: "t",
			impact: "i",
			remediation: "r",
		});
		assert.deepStrictEqual(errors, []);
	});
});

describe("normalizeCve", () => {
	it("extracts CVE from noisy string", () => {
		assert.equal(normalizeCve("See CVE-2024-12345 for details"), "CVE-2024-12345");
	});
	it("returns null for invalid format", () => {
		assert.equal(normalizeCve("CVE-nope"), null);
	});
	it("returns null for empty string", () => {
		assert.equal(normalizeCve(""), null);
	});
});

describe("normalizeCwe", () => {
	it("extracts CWE-79", () => {
		assert.equal(normalizeCwe("CWE-79"), "CWE-79");
	});
	it("extracts from noisy string", () => {
		assert.equal(normalizeCwe("See CWE-89 for SQL injection"), "CWE-89");
	});
	it("returns null for invalid", () => {
		assert.equal(normalizeCwe("CWE-nope"), null);
	});
});

describe("findDuplicate", () => {
	const existing = [
		{ id: "1", title: "SQL Injection", endpoint: "/login" },
		{ id: "2", title: "XSS in search", endpoint: "/search" },
	];

	it("finds exact title duplicate", () => {
		const result = findDuplicate({ title: "SQL Injection" }, existing);
		assert.equal(result, "1");
	});

	it("is case-insensitive", () => {
		const result = findDuplicate({ title: "sql injection" }, existing);
		assert.equal(result, "1");
	});

	it("returns null for no match", () => {
		const result = findDuplicate({ title: "SSRF" }, existing);
		assert.equal(result, null);
	});
});
