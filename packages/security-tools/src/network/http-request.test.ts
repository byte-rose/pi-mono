// packages/security-tools/src/network/http-request.test.ts
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { SecurityScope } from "../scope.js";
import { httpRequestTool } from "./http-request.js";

const openScope: SecurityScope = {
	engagementId: "eng-001",
	mode: "blackbox",
	scanMode: "quick",
	executionMode: "read_only",
	targets: [{ id: "t1", type: "web_application", value: "https://example.com", origins: ["https://example.com"] }],
	exclusions: [],
	allowedActions: ["http_test"],
	filesystem: { readableRoots: [], writableRoots: [], blockedPaths: [], artifactDir: "/tmp" },
	network: {
		allowedDomains: [],
		deniedDomains: ["evil.com"],
		allowedCidrs: [],
		deniedCidrs: [],
		browserEnabled: false,
		proxyEnabled: false,
	},
	reporting: { outputDir: "/tmp/reports", formats: ["markdown"] },
	metadata: { source: "cli", verified: true, createdAt: 0, updatedAt: 0 },
};

const restrictedScope: SecurityScope = {
	...openScope,
	network: {
		...openScope.network,
		allowedDomains: ["allowed.com"],
		deniedDomains: ["evil.com"],
	},
};

const cidrScope: SecurityScope = {
	...openScope,
	network: {
		...openScope.network,
		allowedCidrs: ["10.0.0.0/8"],
		deniedCidrs: ["10.0.1.0/24"],
	},
};

describe("httpRequestTool", () => {
	it("has correct tool metadata", () => {
		const tool = httpRequestTool(openScope);
		assert.strictEqual(tool.name, "http_request");
		assert.ok(tool.description.length > 0);
	});

	it("rejects a domain in deniedDomains", async () => {
		const tool = httpRequestTool(openScope);
		const result = await tool.execute({ url: "https://evil.com/path" });
		assert.strictEqual(result.success, false);
		assert.ok((result.error as string).toLowerCase().includes("scope"));
	});

	it("rejects a domain not in allowedDomains when allowedDomains is non-empty", async () => {
		const tool = httpRequestTool(restrictedScope);
		const result = await tool.execute({ url: "https://notallowed.com/path" });
		assert.strictEqual(result.success, false);
		assert.ok((result.error as string).toLowerCase().includes("scope"));
	});

	it("allows a domain in allowedDomains", async () => {
		const tool = httpRequestTool(restrictedScope);
		const originalFetch = globalThis.fetch;
		globalThis.fetch = async () => new Response("ok", { status: 200, headers: { "content-type": "text/plain" } });
		try {
			const result = await tool.execute({ url: "https://allowed.com/api" });
			assert.strictEqual(result.success, true);
			assert.strictEqual(result.statusCode, 200);
			assert.strictEqual(result.finalUrl, "https://allowed.com/api");
			assert.strictEqual(result.redirectCount, 0);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});

	it("allows any domain when allowedDomains is empty (open scope)", async () => {
		const tool = httpRequestTool(openScope);
		const originalFetch = globalThis.fetch;
		globalThis.fetch = async () => new Response("data", { status: 200, headers: { "content-type": "text/plain" } });
		try {
			const result = await tool.execute({ url: "https://anything.io/path" });
			assert.strictEqual(result.success, true);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});

	it("returns error for unparseable URL", async () => {
		const tool = httpRequestTool(openScope);
		const result = await tool.execute({ url: "not-a-url" });
		assert.strictEqual(result.success, false);
		assert.ok(result.error);
	});

	it("allows subdomain of an allowedDomains entry", async () => {
		const tool = httpRequestTool(restrictedScope);
		const originalFetch = globalThis.fetch;
		globalThis.fetch = async () => new Response("ok", { status: 200, headers: { "content-type": "text/plain" } });
		try {
			const result = await tool.execute({ url: "https://api.allowed.com/v1" });
			assert.strictEqual(result.success, true);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});

	it("allows an IP inside allowedCidrs", async () => {
		const tool = httpRequestTool(cidrScope);
		const originalFetch = globalThis.fetch;
		globalThis.fetch = async () => new Response("ok", { status: 200, headers: { "content-type": "text/plain" } });
		try {
			const result = await tool.execute({ url: "http://10.0.2.15/health" });
			assert.strictEqual(result.success, true);
			assert.strictEqual(result.finalUrl, "http://10.0.2.15/health");
		} finally {
			globalThis.fetch = originalFetch;
		}
	});

	it("blocks an IP in deniedCidrs", async () => {
		const tool = httpRequestTool(cidrScope);
		const result = await tool.execute({ url: "http://10.0.1.99/admin" });
		assert.strictEqual(result.success, false);
		assert.match(String(result.error), /allowedCidrs \/ deniedCidrs/);
	});

	it("blocks an IP outside allowedCidrs when allowedCidrs is non-empty", async () => {
		const tool = httpRequestTool(cidrScope);
		const result = await tool.execute({ url: "http://192.168.1.20/admin" });
		assert.strictEqual(result.success, false);
		assert.match(String(result.error), /allowedCidrs \/ deniedCidrs/);
	});

	it("blocks redirects that leave scope", async () => {
		const tool = httpRequestTool(restrictedScope);
		const originalFetch = globalThis.fetch;
		const calls: string[] = [];
		globalThis.fetch = async (input) => {
			calls.push(String(input));
			return new Response(null, {
				status: 302,
				headers: { location: "https://evil.com/pivot" },
			});
		};
		try {
			const result = await tool.execute({ url: "https://allowed.com/login" });
			assert.strictEqual(result.success, false);
			assert.match(String(result.error), /Redirect blocked/);
			assert.deepStrictEqual(calls, ["https://allowed.com/login"]);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});

	it("follows in-scope redirects when enabled", async () => {
		const tool = httpRequestTool(restrictedScope);
		const originalFetch = globalThis.fetch;
		const calls: string[] = [];
		globalThis.fetch = async (input) => {
			const url = String(input);
			calls.push(url);
			if (url === "https://allowed.com/start") {
				return new Response(null, {
					status: 302,
					headers: { location: "/done" },
				});
			}
			return new Response("ok", { status: 200, headers: { "content-type": "text/plain" } });
		};
		try {
			const result = await tool.execute({ url: "https://allowed.com/start" });
			assert.strictEqual(result.success, true);
			assert.strictEqual(result.finalUrl, "https://allowed.com/done");
			assert.strictEqual(result.redirectCount, 1);
			assert.deepStrictEqual(calls, ["https://allowed.com/start", "https://allowed.com/done"]);
		} finally {
			globalThis.fetch = originalFetch;
		}
	});
});
