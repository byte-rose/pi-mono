import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { calculateCvss, validateCvssBreakdown } from "./cvss.js";

describe("validateCvssBreakdown", () => {
	it("accepts valid breakdown", () => {
		const errors = validateCvssBreakdown({
			attackVector: "N",
			attackComplexity: "L",
			privilegesRequired: "N",
			userInteraction: "N",
			scope: "C",
			confidentiality: "H",
			integrity: "H",
			availability: "H",
		});
		assert.deepStrictEqual(errors, []);
	});

	it("rejects invalid attackVector", () => {
		const errors = validateCvssBreakdown({
			attackVector: "X" as "N",
			attackComplexity: "L",
			privilegesRequired: "N",
			userInteraction: "N",
			scope: "U",
			confidentiality: "N",
			integrity: "N",
			availability: "N",
		});
		assert.ok(errors.some((e) => e.includes("attackVector")));
	});

	it("returns multiple errors for multiple invalid fields", () => {
		const errors = validateCvssBreakdown({
			attackVector: "X" as "N",
			attackComplexity: "X" as "L",
			privilegesRequired: "N",
			userInteraction: "N",
			scope: "U",
			confidentiality: "N",
			integrity: "N",
			availability: "N",
		});
		assert.ok(errors.length >= 2);
	});
});

describe("calculateCvss", () => {
	it("returns score between 0 and 10", () => {
		const result = calculateCvss({
			attackVector: "N",
			attackComplexity: "L",
			privilegesRequired: "N",
			userInteraction: "N",
			scope: "C",
			confidentiality: "H",
			integrity: "H",
			availability: "H",
		});
		assert.ok(result.score >= 0 && result.score <= 10, `score out of range: ${result.score}`);
	});

	it("returns valid severity string", () => {
		const result = calculateCvss({
			attackVector: "N",
			attackComplexity: "L",
			privilegesRequired: "N",
			userInteraction: "N",
			scope: "C",
			confidentiality: "H",
			integrity: "H",
			availability: "H",
		});
		assert.ok(["info", "low", "medium", "high", "critical"].includes(result.severity));
	});

	it("returns CVSS vector string", () => {
		const result = calculateCvss({
			attackVector: "N",
			attackComplexity: "L",
			privilegesRequired: "N",
			userInteraction: "N",
			scope: "C",
			confidentiality: "H",
			integrity: "H",
			availability: "H",
		});
		assert.ok(result.vector.startsWith("CVSS:3.1/"));
	});
});
