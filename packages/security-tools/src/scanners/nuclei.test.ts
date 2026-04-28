import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { SecurityScope } from "../scope.js";
import type { ExecResult, WorkspaceHandle } from "../types.js";
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
		matched: "https://example.com/?x=jndi:ldap://test.example.com/a",
		"matched-at": "https://example.com/?x=jndi:ldap://test.example.com/a",
		description: "Apache Log4j2 <=2.14.1 JNDI features do not protect against attacker-controlled LDAP.",
	}),
	JSON.stringify({
		"template-id": "apache-httpd-version",
		info: { name: "Apache Version Disclosure", severity: "info", tags: ["apache", "version"] },
		host: "https://example.com",
		matched: "Apache/2.4.51",
	}),
].join("\n");

const scope: SecurityScope = {
	engagementId: "eng-nuclei-001",
	mode: "blackbox",
	scanMode: "standard",
	executionMode: "validate",
	targets: [{ id: "t1", type: "web_application", value: "https://example.com", origins: ["https://example.com"] }],
	exclusions: [],
	allowedActions: ["network_scan"],
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

const workspace: WorkspaceHandle = {
	workspaceId: "workspace-1",
	containerId: "container-1",
	workspacePath: "/workspace",
};

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

	it("rejects out-of-scope targets", async () => {
		const tool = nucleiTool(async () => ({ stdout: "", stderr: "", exitCode: 0 }), workspace, scope);
		const result = await tool.execute({ target: "https://outside.example.net" });
		assert.strictEqual(result.success, false);
		assert.match(String(result.error), /outside scope/i);
	});

	it("shell-escapes structured arguments before execution", async () => {
		const commands: string[] = [];
		const exec = async (_workspaceId: string, command: string): Promise<ExecResult> => {
			commands.push(command);
			return { stdout: "", stderr: "", exitCode: 0 };
		};
		const tool = nucleiTool(exec, workspace);
		const result = await tool.execute({
			target: "https://example.com; touch /tmp/pwned",
			template: "cves && echo x",
			timeoutSeconds: 45,
		});
		assert.strictEqual(result.success, true);
		assert.deepStrictEqual(commands, [
			"nuclei -u 'https://example.com; touch /tmp/pwned' -jsonl -t 'cves && echo x' -timeout 45 -silent",
		]);
	});
});
