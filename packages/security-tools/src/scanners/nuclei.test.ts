import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { nucleiTool, parseNucleiOutput } from "./nuclei.js";

const fixtureNdjson = [
	JSON.stringify({
		"template-id": "CVE-2021-44228",
		info: {
			name: "Log4j RCE",
			severity: "critical",
			tags: ["cve", "log4j"],
			reference: ["https://nvd.nist.gov/vuln/detail/CVE-2021-44228"],
		},
		host: "https://example.com",
		matched: `https://example.com/?x=${"jndi:ldap://test.example.com/a"}`,
		"matched-at": `https://example.com/?x=${"jndi:ldap://test.example.com/a"}`,
		description: "Apache Log4j2 <=2.14.1 JNDI features do not protect against attacker-controlled LDAP.",
	}),
	JSON.stringify({
		"template-id": "apache-httpd-version",
		info: { name: "Apache Version Disclosure", severity: "info", tags: ["apache", "version"] },
		host: "https://example.com",
		matched: "Apache/2.4.51",
	}),
].join("\n");

describe("parseNucleiOutput", () => {
	it("parses two findings from fixture NDJSON", () => {
		const findings = parseNucleiOutput(fixtureNdjson);
		assert.strictEqual(findings.length, 2);
	});

	it("maps template-id and severity correctly", () => {
		const findings = parseNucleiOutput(fixtureNdjson);
		assert.strictEqual(findings[0].templateId, "CVE-2021-44228");
		assert.strictEqual(findings[0].severity, "critical");
		assert.strictEqual(findings[0].name, "Log4j RCE");
	});

	it("maps host and matched fields", () => {
		const findings = parseNucleiOutput(fixtureNdjson);
		assert.strictEqual(findings[0].host, "https://example.com");
		assert.ok(findings[0].matched.includes("jndi"));
	});

	it("maps optional description field", () => {
		const findings = parseNucleiOutput(fixtureNdjson);
		assert.ok(findings[0].description?.includes("Log4j2"));
	});

	it("maps optional tags and reference arrays", () => {
		const findings = parseNucleiOutput(fixtureNdjson);
		assert.deepStrictEqual(findings[0].tags, ["cve", "log4j"]);
		assert.ok(Array.isArray(findings[0].reference));
	});

	it("returns empty array for empty input", () => {
		assert.deepStrictEqual(parseNucleiOutput(""), []);
	});

	it("skips malformed lines without throwing", () => {
		const bad = `not-json\n${JSON.stringify({ "template-id": "x", info: { name: "X", severity: "low" }, host: "h", matched: "m" })}`;
		const findings = parseNucleiOutput(bad);
		assert.strictEqual(findings.length, 1);
	});
});

describe("nucleiTool", () => {
	it("has correct tool metadata", () => {
		const tool = nucleiTool(null, undefined);
		assert.strictEqual(tool.name, "nuclei_scan");
		assert.ok(tool.description.length > 0);
	});

	it("returns error when exec is null", async () => {
		const tool = nucleiTool(null, undefined);
		const result = await tool.execute({ target: "https://example.com" });
		assert.strictEqual(result.success, false);
		assert.ok((result.error as string).includes("No sandbox"));
	});
});
