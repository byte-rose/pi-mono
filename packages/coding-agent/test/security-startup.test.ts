import { existsSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { getModel } from "@mariozechner/pi-ai";
import { afterEach, describe, expect, it } from "vitest";
import { parseArgs } from "../src/cli/args.js";
import { DefaultResourceLoader } from "../src/core/resource-loader.js";
import { createAgentSession } from "../src/core/sdk.js";
import {
	createSecurityStartup,
	HTTP_REQUEST_BLOCK_MESSAGE,
	resolveSecurityStartupOptionsFromArgs,
} from "../src/core/security/startup.js";
import { SessionManager } from "../src/core/session-manager.js";
import { SettingsManager } from "../src/core/settings-manager.js";

describe("security startup", () => {
	const tempDirs: string[] = [];

	afterEach(() => {
		for (const dir of tempDirs.splice(0)) {
			if (existsSync(dir)) {
				rmSync(dir, { recursive: true, force: true });
			}
		}
	});

	function createTempDir(): string {
		const dir = join(tmpdir(), `pi-security-startup-${Date.now()}-${Math.random().toString(36).slice(2)}`);
		mkdirSync(dir, { recursive: true });
		tempDirs.push(dir);
		return dir;
	}

	it("prefers CLI security flags over env vars and resolves env fallbacks", () => {
		const cwd = createTempDir();
		const parsed = parseArgs([
			"--security-target",
			"https://cli.example.com",
			"--security-profile",
			"deep",
			"--security-browser-auto-install",
		]);

		const config = resolveSecurityStartupOptionsFromArgs(parsed, cwd, {
			PI_SECURITY_TARGET: "https://env.example.com",
			PI_SECURITY_PROFILE: "quick",
			PI_SECURITY_ENGAGEMENT: "env-engagement",
			PI_SECURITY_WORKSPACE: "env-workspace",
			PI_SECURITY_SKILLS_DIR: "env-skills",
			PI_AGENT_BROWSER_BIN: "/env/bin/agent-browser",
			PI_AGENT_BROWSER_AUTO_INSTALL: "false",
			PI_SECURITY_SANDBOX: "true",
		});

		expect(config).toMatchObject({
			target: "https://cli.example.com",
			profile: "deep",
			engagementId: "env-engagement",
			workspacePath: join(cwd, "env-workspace"),
			skillsDir: join(cwd, "env-skills"),
			agentBrowserBin: "/env/bin/agent-browser",
			agentBrowserAutoInstall: true,
			useSandbox: true,
		});
	});

	it("defaults security profile to standard and workspace to cwd", () => {
		const cwd = createTempDir();
		const parsed = parseArgs(["--security-target", "https://example.com"]);

		const config = resolveSecurityStartupOptionsFromArgs(parsed, cwd, {});

		expect(config?.target).toBe("https://example.com");
		expect(config?.profile).toBe("standard");
		expect(config?.workspacePath).toBe(cwd);
		expect(config?.agentBrowserAutoInstall).toBe(true);
		expect(config?.useSandbox).toBe(false);
	});

	it("injects the security prompt, enables browser_action, and blocks http_request", async () => {
		const cwd = createTempDir();
		const agentDir = join(cwd, "agent");
		mkdirSync(agentDir, { recursive: true });

		const parsed = parseArgs(["--security-target", "https://example.com", "--security-profile", "standard"]);
		const config = resolveSecurityStartupOptionsFromArgs(parsed, cwd, {});
		expect(config).toBeDefined();

		const originalHome = process.env.HOME;
		process.env.HOME = cwd;
		try {
			const securityStartup = await createSecurityStartup(config!, {
				runDir: join(cwd, "security-run"),
			});
			const settingsManager = SettingsManager.create(cwd, agentDir);
			const sessionManager = SessionManager.inMemory();
			const resourceLoader = new DefaultResourceLoader({
				cwd,
				agentDir,
				settingsManager,
				noExtensions: true,
				noSkills: true,
				noPromptTemplates: true,
				noThemes: true,
				appendSystemPromptOverride: (base) => [...base, securityStartup.systemPrompt],
			});
			await resourceLoader.reload();

			const { session } = await createAgentSession({
				cwd,
				agentDir,
				model: getModel("anthropic", "claude-sonnet-4-5")!,
				settingsManager,
				sessionManager,
				resourceLoader,
				customTools: securityStartup.customTools,
			});

			expect(session.getActiveToolNames()).toContain("browser_action");
			expect(session.getActiveToolNames()).toContain("http_request");
			expect(session.systemPrompt).toContain(securityStartup.systemPrompt);

			const httpRequest = session.agent.state.tools.find((tool) => tool.name === "http_request");
			expect(httpRequest).toBeDefined();

			const result = await httpRequest!.execute(
				"tool-http-request",
				{ url: "https://example.com" },
				undefined,
				undefined,
			);

			expect(result.details).toMatchObject({
				blocked: true,
				reason: HTTP_REQUEST_BLOCK_MESSAGE,
			});
			expect(JSON.stringify(result)).toContain(HTTP_REQUEST_BLOCK_MESSAGE);
			session.dispose();
			await securityStartup.cleanup();
		} finally {
			process.env.HOME = originalHome;
		}
	});
});
