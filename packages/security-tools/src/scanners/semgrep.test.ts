import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { parseSemgrepOutput, semgrepTool } from "./semgrep.js";

const fixtureJson = JSON.stringify({
	results: [
		{
			check_id: "python.django.security.injection.tainted-sql-string.tainted-sql-string",
			path: "app/views.py",
			start: { line: 42, col: 1 },
			end: { line: 42, col: 80 },
			extra: {
				message: "User-controlled data used in SQL query without parameterization.",
				severity: "ERROR",
				metadata: {
					cwe: ["CWE-89: Improper Neutralization of Special Elements used in an SQL Command"],
				},
			},
		},
	],
	errors: [],
});

const fixtureWithErrors = JSON.stringify({
	results: [],
	errors: [{ message: "Could not parse file: app/broken.py", type: "ParseError" }],
});

describe("parseSemgrepOutput", () => {
	it("parses one finding from fixture", () => {
		const { findings } = parseSemgrepOutput(fixtureJson);
		assert.strictEqual(findings.length, 1);
	});

	it("maps ruleId, path, line, message, severity", () => {
		const { findings } = parseSemgrepOutput(fixtureJson);
		const f = findings[0];
		assert.ok(f.ruleId.includes("tainted-sql"));
		assert.strictEqual(f.path, "app/views.py");
		assert.strictEqual(f.line, 42);
		assert.ok(f.message.includes("SQL"));
		assert.strictEqual(f.severity, "ERROR");
	});

	it("extracts CWE identifiers from metadata", () => {
		const { findings } = parseSemgrepOutput(fixtureJson);
		assert.ok(Array.isArray(findings[0].cwe));
		assert.ok((findings[0].cwe as string[]).some((c) => c.startsWith("CWE-89")));
	});

	it("returns empty findings and empty errors for empty results", () => {
		const empty = JSON.stringify({ results: [], errors: [] });
		const { findings, errors } = parseSemgrepOutput(empty);
		assert.strictEqual(findings.length, 0);
		assert.strictEqual(errors.length, 0);
	});

	it("captures errors array", () => {
		const { errors } = parseSemgrepOutput(fixtureWithErrors);
		assert.strictEqual(errors.length, 1);
		assert.ok(errors[0].includes("ParseError"));
	});

	it("returns parse error for malformed JSON", () => {
		const { findings, errors } = parseSemgrepOutput("not-json");
		assert.strictEqual(findings.length, 0);
		assert.strictEqual(errors.length, 1);
	});
});

describe("semgrepTool", () => {
	it("has correct tool metadata", () => {
		const tool = semgrepTool(null, undefined);
		assert.strictEqual(tool.name, "semgrep_scan");
		assert.ok(tool.description.length > 0);
	});

	it("returns error when exec is null", async () => {
		const tool = semgrepTool(null, undefined);
		const result = await tool.execute({ config: "auto", path: "." });
		assert.strictEqual(result.success, false);
		assert.ok((result.error as string).includes("No sandbox"));
	});
});
