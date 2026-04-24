import assert from "node:assert/strict";
import { readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import type { SecurityScope } from "../scope.js";
import { browserActionTool } from "./browser-action.js";

const TEST_RUN_DIR = join(tmpdir(), `nyati-browser-action-${Date.now()}`);

const enabledScope: SecurityScope = {
	engagementId: "eng-browser-001",
	mode: "blackbox",
	scanMode: "standard",
	executionMode: "validate",
	targets: [{ id: "t1", type: "web_application", value: "https://example.com", origins: ["https://example.com"] }],
	exclusions: [],
	allowedActions: ["browser_test", "create_reports"],
	filesystem: { readableRoots: [], writableRoots: [], blockedPaths: [], artifactDir: TEST_RUN_DIR },
	network: {
		allowedDomains: ["example.com"],
		deniedDomains: ["denied.example.com"],
		allowedCidrs: [],
		deniedCidrs: [],
		browserEnabled: true,
		proxyEnabled: false,
	},
	reporting: { outputDir: join(TEST_RUN_DIR, "reports"), formats: ["markdown"] },
	metadata: { source: "cli", verified: true, createdAt: 0, updatedAt: 0 },
};

describe("browserActionTool", () => {
	afterEach(async () => {
		await rm(TEST_RUN_DIR, { recursive: true, force: true });
	});

	it("has correct tool metadata", () => {
		const tool = browserActionTool(enabledScope, TEST_RUN_DIR);
		assert.strictEqual(tool.name, "browser_action");
		assert.ok(tool.description.includes("Agent Browser"));
	});

	it("rejects browser actions when browser workflows are disabled", async () => {
		const tool = browserActionTool(
			{
				...enabledScope,
				allowedActions: ["create_reports"],
				network: { ...enabledScope.network, browserEnabled: false },
			},
			TEST_RUN_DIR,
		);

		const result = await tool.execute({ action: "snapshot" });
		assert.strictEqual(result.success, false);
		assert.match(String(result.error), /not enabled/i);
	});

	it("rejects open actions outside the allowed scope", async () => {
		const tool = browserActionTool(enabledScope, TEST_RUN_DIR, {
			runCommand: async () => ({ stdout: "", stderr: "", exitCode: 0 }),
		});

		const result = await tool.execute({ action: "open", url: "https://evil.com" });
		assert.strictEqual(result.success, false);
		assert.match(String(result.error), /outside scope/i);
	});

	it("builds a scoped agent-browser snapshot command and config", async () => {
		let capturedArgs: string[] | undefined;

		const tool = browserActionTool(enabledScope, TEST_RUN_DIR, {
			agentBrowserBin: "/usr/local/bin/agent-browser",
			runCommand: async (_spec, args) => {
				capturedArgs = args;
				return { stdout: '@e1 [link] "Home"', stderr: "", exitCode: 0 };
			},
		});

		const result = await tool.execute({ action: "snapshot", session: "example-session" });

		assert.strictEqual(result.success, true);
		assert.ok(capturedArgs);
		assert.ok(capturedArgs?.includes("--config"));
		assert.ok(capturedArgs?.includes("snapshot"));
		assert.ok(capturedArgs?.includes("-i"));
		assert.ok(capturedArgs?.includes("-c"));
		assert.strictEqual(result.session, "example-session");

		const configIndex = capturedArgs?.indexOf("--config") ?? -1;
		assert.ok(configIndex >= 0);
		const configPath = capturedArgs?.[configIndex + 1];
		assert.ok(configPath);

		const config = JSON.parse(await readFile(configPath as string, "utf-8")) as { allowedDomains?: string[] };
		assert.deepStrictEqual(config.allowedDomains, ["example.com", "*.example.com"]);
		assert.strictEqual(result.stdout, '@e1 [link] "Home"');
	});

	it("resolves the packaged agent-browser dependency before falling back to failure", async () => {
		let capturedCommand: string | undefined;
		let capturedPrefixArgs: string[] | undefined;
		let capturedSource: string | undefined;

		const tool = browserActionTool(enabledScope, TEST_RUN_DIR, {
			resolvePackagedAgentBrowserScript: () => "/pkg/node_modules/agent-browser/bin/agent-browser.js",
			runCommand: async (spec) => {
				capturedCommand = spec.command;
				capturedPrefixArgs = spec.prefixArgs;
				capturedSource = spec.source;
				return { stdout: '@e1 [link] "Home"', stderr: "", exitCode: 0 };
			},
		});

		const result = await tool.execute({ action: "snapshot" });
		assert.strictEqual(result.success, true);
		assert.strictEqual(capturedSource, "packaged");
		assert.strictEqual(capturedCommand, process.execPath);
		assert.deepStrictEqual(capturedPrefixArgs, ["/pkg/node_modules/agent-browser/bin/agent-browser.js"]);
	});

	it("prefers an explicit agent-browser binary over the packaged dependency", async () => {
		let capturedCommand: string | undefined;
		let capturedSource: string | undefined;

		const tool = browserActionTool(enabledScope, TEST_RUN_DIR, {
			agentBrowserBin: "/custom/agent-browser",
			resolvePackagedAgentBrowserScript: () => "/pkg/node_modules/agent-browser/bin/agent-browser.js",
			runCommand: async (spec) => {
				capturedCommand = spec.command;
				capturedSource = spec.source;
				return { stdout: '@e1 [link] "Home"', stderr: "", exitCode: 0 };
			},
		});

		const result = await tool.execute({ action: "snapshot" });
		assert.strictEqual(result.success, true);
		assert.strictEqual(capturedSource, "explicit");
		assert.strictEqual(capturedCommand, "/custom/agent-browser");
	});

	it("provisions the browser runtime through the resolved packaged CLI", async () => {
		const invocations: Array<{ source: string; args: string[] }> = [];

		const tool = browserActionTool(enabledScope, TEST_RUN_DIR, {
			resolvePackagedAgentBrowserScript: () => "/pkg/node_modules/agent-browser/bin/agent-browser.js",
			runCommand: async (spec, args) => {
				invocations.push({ source: spec.source, args });

				if (invocations.length === 1) {
					return {
						stdout: "",
						stderr: "Browser runtime missing. Run `agent-browser install` before using this command.",
						exitCode: 1,
					};
				}

				if (invocations.length === 2) {
					return { stdout: "installed", stderr: "", exitCode: 0 };
				}

				return { stdout: '@e1 [link] "Home"', stderr: "", exitCode: 0 };
			},
		});

		const result = await tool.execute({ action: "snapshot" });
		assert.strictEqual(result.success, true);
		assert.deepStrictEqual(invocations, [
			{
				source: "packaged",
				args: [
					"--config",
					join(TEST_RUN_DIR, "agent-browser", "config.json"),
					"--session",
					"eng-browser-001",
					"snapshot",
					"-i",
					"-c",
				],
			},
			{ source: "packaged", args: ["install"] },
			{
				source: "packaged",
				args: [
					"--config",
					join(TEST_RUN_DIR, "agent-browser", "config.json"),
					"--session",
					"eng-browser-001",
					"snapshot",
					"-i",
					"-c",
				],
			},
		]);
	});

	it("reports a missing packaged CLI dependency separately from a missing browser runtime", async () => {
		const tool = browserActionTool(enabledScope, TEST_RUN_DIR, {
			resolvePackagedAgentBrowserScript: () => undefined,
		});

		const result = await tool.execute({ action: "snapshot" });
		assert.strictEqual(result.success, false);
		assert.match(String(result.error), /CLI package 'agent-browser' is not installed/i);
	});

	it("surfaces a clear recovery command when the browser runtime is missing", async () => {
		const tool = browserActionTool(enabledScope, TEST_RUN_DIR, {
			agentBrowserAutoInstall: false,
			resolvePackagedAgentBrowserScript: () => "/pkg/node_modules/agent-browser/bin/agent-browser.js",
			runCommand: async () => ({
				stdout: "",
				stderr: "Browser runtime missing. Run `agent-browser install` before using this command.",
				exitCode: 1,
			}),
		});

		const result = await tool.execute({ action: "snapshot" });
		assert.strictEqual(result.success, false);
		assert.match(String(result.error), /browser runtime is not installed/i);
		assert.match(
			String(result.error),
			new RegExp(`${process.execPath.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")} .*agent-browser\\.js.* install`),
		);
	});
});
