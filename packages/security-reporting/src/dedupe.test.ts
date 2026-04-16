import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { Finding } from "@byte-rose/nyati-security-artifacts";
import { dedupeFindings } from "./dedupe.js";

const base: Finding = {
	id: "1",
	title: "SQL Injection",
	category: "injection",
	severity: "high",
	confidence: "high",
	status: "candidate",
	targets: [],
	evidenceIds: [],
	summary: "s",
	technicalAnalysis: "t",
	impact: "i",
	remediation: "r",
	createdAt: 1000,
	updatedAt: 1000,
};

describe("dedupeFindings", () => {
	it("removes exact title duplicates (case-insensitive)", () => {
		const dupes: Finding[] = [{ ...base, id: "2", title: "sql injection" }];
		const result = dedupeFindings([base, ...dupes]);
		assert.equal(result.length, 1);
		assert.equal(result[0]!.id, "1");
	});

	it("keeps distinct findings", () => {
		const other: Finding = { ...base, id: "3", title: "XSS" };
		const result = dedupeFindings([base, other]);
		assert.equal(result.length, 2);
	});

	it("returns empty array for empty input", () => {
		assert.deepStrictEqual(dedupeFindings([]), []);
	});
});
