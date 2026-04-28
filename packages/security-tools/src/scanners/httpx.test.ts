import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { SecurityScope } from "../scope.js";
import type { ExecResult, WorkspaceHandle } from "../types.js";
import { httpxTool, parseHttpxOutput } from "./httpx.js";

const fixtureNdjson = [
	JSON.stringify({
		url: "https://example.com",
		status_code: 200,
		title: "Example Domain",
		tech: ["Nginx", "OpenSSL"],
		content_length: 1256,
		response_time: "142ms",
	}),
	JSON.stringify({
		url: "https://example.com/login",
		status_code: 302,
		title: "",
		content_length: 0,
		response_time: "38ms",
	}),
].join("\n");

const scope: SecurityScope = {
	engagementId: "eng-httpx-001",
	mode: "blackbox",
	scanMode: "standard",
	executionMode: "validate",
	targets: [{ id: "t1", type: "web_application", value: "https://example.com", origins: ["https://example.com"] }],
	exclusions: [],
	allowedActions: ["network_scan"],
	filesystem: { readableRoots: [], writableRoots: [], blockedPaths: [], artifactDir: "/tmp/run" },
	network: {
		allowedDomains: ["example.com"],
		deniedDomains: ["blocked.example.com"],
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

describe("parseHttpxOutput", () => {
	it("parses two results from fixture NDJSON", () => {
		const results = parseHttpxOutput(fixtureNdjson);
		assert.strictEqual(results.length, 2);
	});

	it("maps url and statusCode", () => {
		const results = parseHttpxOutput(fixtureNdjson);
		assert.strictEqual(results[0].url, "https://example.com");
		assert.strictEqual(results[0].statusCode, 200);
	});

	it("maps optional title and technologies", () => {
		const results = parseHttpxOutput(fixtureNdjson);
		assert.strictEqual(results[0].title, "Example Domain");
		assert.deepStrictEqual(results[0].technologies, ["Nginx", "OpenSSL"]);
	});

	it("maps contentLength and responseTime", () => {
		const results = parseHttpxOutput(fixtureNdjson);
		assert.strictEqual(results[0].contentLength, 1256);
		assert.strictEqual(results[0].responseTime, "142ms");
	});

	it("handles missing optional fields gracefully", () => {
		const results = parseHttpxOutput(fixtureNdjson);
		assert.strictEqual(results[1].technologies, undefined);
	});

	it("returns empty array for empty input", () => {
		assert.deepStrictEqual(parseHttpxOutput(""), []);
	});

	it("skips malformed lines", () => {
		const mixed = `bad-line\n${JSON.stringify({ url: "https://x.com", status_code: 200 })}`;
		const results = parseHttpxOutput(mixed);
		assert.strictEqual(results.length, 1);
	});
});

describe("httpxTool", () => {
	it("has correct tool metadata", () => {
		const tool = httpxTool(null, undefined);
		assert.strictEqual(tool.name, "httpx_probe");
		assert.ok(tool.description.length > 0);
	});

	it("returns error when exec is null", async () => {
		const tool = httpxTool(null, undefined);
		const result = await tool.execute({ target: "https://example.com" });
		assert.strictEqual(result.success, false);
		assert.ok((result.error as string).includes("No sandbox"));
	});

	it("rejects out-of-scope targets", async () => {
		const tool = httpxTool(async () => ({ stdout: "", stderr: "", exitCode: 0 }), workspace, scope);
		const result = await tool.execute({ target: "https://outside.example.net" });
		assert.strictEqual(result.success, false);
		assert.match(String(result.error), /outside scope/i);
	});

	it("shell-escapes structured arguments before execution", async () => {
		const commands: string[] = [];
		const exec = async (_workspaceId: string, command: string): Promise<ExecResult> => {
			commands.push(command);
			return { stdout: fixtureNdjson, stderr: "", exitCode: 0 };
		};
		const tool = httpxTool(exec, workspace);
		const result = await tool.execute({
			target: "https://example.com; curl https://evil.test",
			timeoutSeconds: 7,
		});
		assert.strictEqual(result.success, true);
		assert.deepStrictEqual(commands, [
			"httpx -u 'https://example.com; curl https://evil.test' -json -status-code -title -tech-detect -content-length -response-time -silent -timeout 7",
		]);
	});
});
