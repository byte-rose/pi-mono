import { spawn } from "node:child_process";
import { mkdir, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { type Static, Type } from "@sinclair/typebox";
import type { SecurityScope } from "../scope.js";
import type { SecurityTool } from "../types.js";

const browserActionSchema = Type.Object({
	action: Type.Union([
		Type.Literal("open"),
		Type.Literal("snapshot"),
		Type.Literal("click"),
		Type.Literal("fill"),
		Type.Literal("press"),
		Type.Literal("wait"),
		Type.Literal("screenshot"),
		Type.Literal("get_text"),
		Type.Literal("close"),
	]),
	session: Type.Optional(Type.String({ description: "Named browser session. Defaults to the engagement ID." })),
	url: Type.Optional(Type.String({ description: "URL to open for the open action." })),
	ref: Type.Optional(Type.String({ description: "Element reference like @e3 for click/fill/get_text." })),
	text: Type.Optional(Type.String({ description: "Text to fill into an element." })),
	key: Type.Optional(Type.String({ description: "Key to press, for example Enter or Escape." })),
	path: Type.Optional(
		Type.String({ description: "Screenshot output path. Relative paths are resolved inside the run directory." }),
	),
	interactive: Type.Optional(Type.Boolean({ description: "Snapshot only interactive elements. Default: true." })),
	compact: Type.Optional(Type.Boolean({ description: "Compact snapshot output. Default: true." })),
	includeUrls: Type.Optional(Type.Boolean({ description: "Include link URLs in snapshot output." })),
	selector: Type.Optional(Type.String({ description: "Scope snapshot output to a CSS selector." })),
	depth: Type.Optional(Type.Number({ description: "Maximum snapshot depth." })),
	annotate: Type.Optional(Type.Boolean({ description: "Annotate screenshots with element labels." })),
	loadState: Type.Optional(
		Type.Union([Type.Literal("load"), Type.Literal("domcontentloaded"), Type.Literal("networkidle")]),
	),
	all: Type.Optional(Type.Boolean({ description: "Close all browser sessions for the close action." })),
	timeoutSeconds: Type.Optional(Type.Number({ description: "Timeout in seconds. Default: 60." })),
});

type BrowserActionInput = Static<typeof browserActionSchema>;

interface BrowserCommandResult {
	stdout: string;
	stderr: string;
	exitCode: number;
}

interface BrowserToolOptions {
	agentBrowserBin?: string;
	agentBrowserUseNpx?: boolean;
	agentBrowserAutoInstall?: boolean;
	env?: NodeJS.ProcessEnv;
	runCommand?: BrowserCommandRunner;
	resolvePackagedAgentBrowserScript?: () => string | undefined;
}

interface BrowserCommandSpec {
	command: string;
	prefixArgs: string[];
	explicitBin: boolean;
	source: "explicit" | "packaged" | "npx";
	recoveryCommand: string;
	displayCommand: string;
}

interface BrowserCommandRunnerOptions {
	cwd: string;
	env: NodeJS.ProcessEnv;
	timeoutMs: number;
}

type BrowserCommandRunner = (
	spec: BrowserCommandSpec,
	args: string[],
	options: BrowserCommandRunnerOptions,
) => Promise<BrowserCommandResult>;

function isDomainAllowed(scope: SecurityScope, hostname: string): boolean {
	if (!hostname.trim()) return false;
	if (scope.network.deniedDomains.some((d) => hostname === d || hostname.endsWith(`.${d}`))) return false;
	if (scope.network.allowedDomains.length === 0) return true;
	return scope.network.allowedDomains.some((d) => hostname === d || hostname.endsWith(`.${d}`));
}

function sanitizeSessionName(value: string): string {
	const normalized = value.trim().replace(/[^A-Za-z0-9._-]+/g, "-");
	const collapsed = normalized.replace(/^-+/, "").replace(/-+$/, "");
	return collapsed.length > 0 ? collapsed : "security-browser";
}

function expandAllowedDomains(scope: SecurityScope): string[] {
	const expanded = new Set<string>();

	for (const domain of scope.network.allowedDomains) {
		const normalized = domain.trim();
		if (!normalized) continue;
		expanded.add(normalized);
		if (!normalized.startsWith("*.")) {
			expanded.add(`*.${normalized}`);
		}
	}

	return [...expanded];
}

function quoteCommandPart(value: string): string {
	return /^[A-Za-z0-9_./:=+-]+$/.test(value) ? value : JSON.stringify(value);
}

function formatCommand(command: string, args: string[]): string {
	return [command, ...args].map(quoteCommandPart).join(" ");
}

function resolvePackagedAgentBrowserScript(): string | undefined {
	try {
		const require = createRequire(import.meta.url);
		return require.resolve("agent-browser/bin/agent-browser.js");
	} catch {
		return undefined;
	}
}

function resolveBrowserCommand(options?: BrowserToolOptions): BrowserCommandSpec | undefined {
	const env = options?.env ?? process.env;
	const useNpxEnv = env.NYATI_AGENT_BROWSER_USE_NPX ?? env.PI_AGENT_BROWSER_USE_NPX;
	const useNpx =
		options?.agentBrowserUseNpx ??
		(useNpxEnv ? ["1", "true", "yes", "on"].includes(useNpxEnv.trim().toLowerCase()) : false);
	const configuredBin =
		options?.agentBrowserBin?.trim() || env.NYATI_AGENT_BROWSER_BIN?.trim() || env.PI_AGENT_BROWSER_BIN?.trim();

	if (configuredBin) {
		return {
			command: configuredBin,
			prefixArgs: [],
			explicitBin: true,
			source: "explicit",
			recoveryCommand: formatCommand(configuredBin, ["install"]),
			displayCommand: configuredBin,
		};
	}

	if (useNpx) {
		return {
			command: "npx",
			prefixArgs: ["agent-browser"],
			explicitBin: false,
			source: "npx",
			recoveryCommand: "npx agent-browser install",
			displayCommand: "npx agent-browser",
		};
	}

	const packagedScript = options?.resolvePackagedAgentBrowserScript?.() ?? resolvePackagedAgentBrowserScript();
	if (!packagedScript) {
		return undefined;
	}

	return {
		command: process.execPath,
		prefixArgs: [packagedScript],
		explicitBin: false,
		source: "packaged",
		recoveryCommand: formatCommand(process.execPath, [packagedScript, "install"]),
		displayCommand: formatCommand(process.execPath, [packagedScript]),
	};
}

async function runBrowserCommand(
	spec: BrowserCommandSpec,
	args: string[],
	options: BrowserCommandRunnerOptions,
): Promise<BrowserCommandResult> {
	return await new Promise((resolveResult) => {
		const child = spawn(spec.command, [...spec.prefixArgs, ...args], {
			cwd: options.cwd,
			env: options.env,
			stdio: ["ignore", "pipe", "pipe"],
		});

		let stdout = "";
		let stderr = "";
		let timedOut = false;

		const timeout = setTimeout(() => {
			timedOut = true;
			child.kill("SIGTERM");
		}, options.timeoutMs);

		child.stdout.on("data", (chunk: Buffer | string) => {
			stdout += chunk.toString();
		});
		child.stderr.on("data", (chunk: Buffer | string) => {
			stderr += chunk.toString();
		});
		child.on("error", (error) => {
			clearTimeout(timeout);
			const exitCode = "code" in error && error.code === "ENOENT" ? 127 : 1;
			resolveResult({
				stdout,
				stderr: error.message,
				exitCode,
			});
		});
		child.on("close", (exitCode) => {
			clearTimeout(timeout);
			resolveResult({
				stdout,
				stderr: timedOut ? `${stderr}\nTimed out after ${options.timeoutMs}ms`.trim() : stderr,
				exitCode: timedOut ? 124 : (exitCode ?? 1),
			});
		});
	});
}

function createBrowserConfig(scope: SecurityScope, profileDir: string, downloadDir: string): Record<string, unknown> {
	const config: Record<string, unknown> = {
		profile: profileDir,
		downloadPath: downloadDir,
		contentBoundaries: true,
		maxOutput: 50_000,
	};

	const allowedDomains = expandAllowedDomains(scope);
	if (allowedDomains.length > 0) {
		config.allowedDomains = allowedDomains;
	}

	return config;
}

function requireString(
	value: string | undefined,
	field: string,
): { ok: true; value: string } | { ok: false; error: string } {
	if (value && value.trim().length > 0) {
		return { ok: true, value };
	}

	return { ok: false, error: `${field} is required for this browser action.` };
}

function buildBrowserArgs(
	input: BrowserActionInput,
	sessionName: string,
	configPath: string,
	screenshotPath: string | undefined,
): { ok: true; args: string[] } | { ok: false; error: string } {
	const args = ["--config", configPath, "--session", sessionName];

	switch (input.action) {
		case "open": {
			const url = requireString(input.url, "url");
			if (!url.ok) return url;
			return { ok: true, args: [...args, "open", url.value] };
		}
		case "snapshot": {
			const snapshotArgs = [...args, "snapshot"];
			if (input.interactive ?? true) snapshotArgs.push("-i");
			if (input.compact ?? true) snapshotArgs.push("-c");
			if (input.includeUrls) snapshotArgs.push("-u");
			if (input.depth !== undefined) snapshotArgs.push("-d", String(input.depth));
			if (input.selector) snapshotArgs.push("-s", input.selector);
			return { ok: true, args: snapshotArgs };
		}
		case "click": {
			const ref = requireString(input.ref, "ref");
			if (!ref.ok) return ref;
			return { ok: true, args: [...args, "click", ref.value] };
		}
		case "fill": {
			const ref = requireString(input.ref, "ref");
			if (!ref.ok) return ref;
			const text = requireString(input.text, "text");
			if (!text.ok) return text;
			return { ok: true, args: [...args, "fill", ref.value, text.value] };
		}
		case "press": {
			const key = requireString(input.key, "key");
			if (!key.ok) return key;
			return { ok: true, args: [...args, "press", key.value] };
		}
		case "wait": {
			const waitArgs = [...args, "wait"];
			if (input.loadState) waitArgs.push("--load", input.loadState);
			return { ok: true, args: waitArgs };
		}
		case "screenshot": {
			if (!screenshotPath) {
				return { ok: false, error: "path could not be resolved for the screenshot action." };
			}
			const screenshotArgs = [...args, "screenshot"];
			if (input.annotate) screenshotArgs.push("--annotate");
			screenshotArgs.push(screenshotPath);
			return { ok: true, args: screenshotArgs };
		}
		case "get_text": {
			const ref = requireString(input.ref, "ref");
			if (!ref.ok) return ref;
			return { ok: true, args: [...args, "get", "text", ref.value] };
		}
		case "close": {
			const closeArgs = [...args, "close"];
			if (input.all) closeArgs.push("--all");
			return { ok: true, args: closeArgs };
		}
	}

	return { ok: false, error: `Unsupported browser action: ${String(input.action)}` };
}

function resolveScreenshotPath(browserRoot: string, requestedPath: string | undefined): string {
	if (requestedPath) {
		return resolve(browserRoot, requestedPath);
	}

	return join(browserRoot, "screenshots", `${Date.now()}.png`);
}

function createMissingCliPackageError(): string {
	return (
		"Agent Browser CLI package 'agent-browser' is not installed. " +
		"Install it with 'npm install agent-browser' or set NYATI_AGENT_BROWSER_BIN / PI_AGENT_BROWSER_BIN."
	);
}

function createMissingCliError(spec: BrowserCommandSpec, result?: BrowserCommandResult): string {
	const base =
		spec.source === "explicit"
			? `Agent Browser CLI was not found at '${spec.command}'. Run '${spec.recoveryCommand}' or update NYATI_AGENT_BROWSER_BIN / PI_AGENT_BROWSER_BIN.`
			: spec.source === "npx"
				? `Agent Browser CLI was not available via npx. Run '${spec.recoveryCommand}' or disable npx mode.`
				: `Agent Browser CLI could not be executed from '${spec.displayCommand}'. Reinstall 'agent-browser' or set NYATI_AGENT_BROWSER_BIN / PI_AGENT_BROWSER_BIN.`;
	const details = result
		? [result.stderr.trim(), result.stdout.trim()].filter((value) => value.length > 0).join("\n")
		: "";
	return details.length > 0 ? `${base}\n\nCLI output:\n${details}` : base;
}

function shouldAutoInstall(options: BrowserToolOptions | undefined): boolean {
	const env = options?.env ?? process.env;
	const envValue = env.NYATI_AGENT_BROWSER_AUTO_INSTALL ?? env.PI_AGENT_BROWSER_AUTO_INSTALL;
	const envSetting = envValue ? ["1", "true", "yes", "on"].includes(envValue.trim().toLowerCase()) : undefined;
	return options?.agentBrowserAutoInstall ?? envSetting ?? true;
}

function isBrowserRuntimeMissing(result: BrowserCommandResult): boolean {
	const combined = `${result.stderr}\n${result.stdout}`.toLowerCase();
	return [
		"agent-browser install",
		"browser runtime",
		"runtime not installed",
		"playwright browser",
		"browser binaries",
		"no compatible browser executable",
	].some((pattern) => combined.includes(pattern));
}

async function tryAutoInstall(
	spec: BrowserCommandSpec,
	options: BrowserToolOptions | undefined,
	cwd: string,
	env: NodeJS.ProcessEnv,
): Promise<BrowserCommandResult | undefined> {
	if (!shouldAutoInstall(options)) {
		return undefined;
	}

	const runner = options?.runCommand ?? runBrowserCommand;
	return await runner(spec, ["install"], {
		cwd,
		env,
		timeoutMs: 10 * 60 * 1000,
	});
}

function createMissingRuntimeError(spec: BrowserCommandSpec, result: BrowserCommandResult): string {
	const details = [result.stderr.trim(), result.stdout.trim()].filter((value) => value.length > 0).join("\n");
	const base = `Agent Browser browser runtime is not installed. Run '${spec.recoveryCommand}'.`;
	return details.length > 0 ? `${base}\n\nCLI output:\n${details}` : base;
}

function createInstallFailureError(spec: BrowserCommandSpec, result: BrowserCommandResult): string {
	const installMessage = `Agent Browser runtime provisioning failed. Run '${spec.recoveryCommand}'.`;
	const details = [result.stderr.trim(), result.stdout.trim()].filter((value) => value.length > 0).join("\n");
	return details.length > 0 ? `${installMessage}\n\nInstall attempt failed:\n${details}` : installMessage;
}

export function browserActionTool(
	scope: SecurityScope,
	runDir: string,
	options?: BrowserToolOptions,
): SecurityTool<BrowserActionInput> {
	const runCommand = options?.runCommand ?? runBrowserCommand;
	const env = options?.env ?? process.env;

	return {
		name: "browser_action",
		label: "Browser Action",
		description:
			"Use Agent Browser as the first-class web workflow for scoped browsing, recon, authentication flows, screenshots, and multi-step testing. " +
			"Typical sequence: open the target URL, snapshot interactive elements, click or fill refs, wait for page changes, then snapshot again. " +
			"Refs become stale after navigation or DOM changes, so always re-snapshot before the next interaction.",
		parameters: browserActionSchema,
		async execute(input) {
			if (!scope.network.browserEnabled || !scope.allowedActions.includes("browser_test")) {
				return { success: false, error: "Browser workflows are not enabled in the current security scope." };
			}

			const browserRoot = join(runDir, "agent-browser");
			const profileDir = join(browserRoot, "profile");
			const downloadDir = join(browserRoot, "downloads");
			const screenshotPath =
				input.action === "screenshot" ? resolveScreenshotPath(browserRoot, input.path) : undefined;
			const sessionName = sanitizeSessionName(input.session ?? scope.engagementId);

			if (input.action === "open") {
				let hostname: string;
				try {
					hostname = new URL(input.url ?? "").hostname;
				} catch {
					return { success: false, error: `Invalid URL: ${input.url ?? ""}` };
				}

				if (!isDomainAllowed(scope, hostname)) {
					return {
						success: false,
						error: `Domain '${hostname}' is outside scope. Browser actions must stay within the configured targets.`,
					};
				}
			}

			await mkdir(profileDir, { recursive: true });
			await mkdir(downloadDir, { recursive: true });
			await mkdir(join(browserRoot, "screenshots"), { recursive: true });

			const configPath = join(browserRoot, "config.json");
			const config = createBrowserConfig(scope, profileDir, downloadDir);
			await writeFile(configPath, JSON.stringify(config, null, 2));

			const builtArgs = buildBrowserArgs(input, sessionName, configPath, screenshotPath);
			if (!builtArgs.ok) {
				return { success: false, error: builtArgs.error };
			}

			const spec = resolveBrowserCommand(options);
			if (!spec) {
				return { success: false, error: createMissingCliPackageError() };
			}

			const timeoutMs = (input.timeoutSeconds ?? 60) * 1000;
			let result = await runCommand(spec, builtArgs.args, {
				cwd: browserRoot,
				env,
				timeoutMs,
			});

			if (result.exitCode === 127) {
				return { success: false, error: createMissingCliError(spec, result) };
			}

			if (result.exitCode !== 0 && isBrowserRuntimeMissing(result)) {
				const installResult = await tryAutoInstall(spec, options, browserRoot, env);
				if (!installResult) {
					return { success: false, error: createMissingRuntimeError(spec, result) };
				}

				if (installResult.exitCode !== 0) {
					return { success: false, error: createInstallFailureError(spec, installResult) };
				}

				result = await runCommand(spec, builtArgs.args, {
					cwd: browserRoot,
					env,
					timeoutMs,
				});
				if (result.exitCode === 127) {
					return { success: false, error: createMissingCliError(spec, result) };
				}
				if (result.exitCode !== 0 && isBrowserRuntimeMissing(result)) {
					return { success: false, error: createMissingRuntimeError(spec, result) };
				}
			}

			return {
				success: result.exitCode === 0,
				action: input.action,
				session: sessionName,
				command: spec.displayCommand,
				stdout: result.stdout,
				stderr: result.stderr,
				exitCode: result.exitCode,
				...(screenshotPath ? { path: screenshotPath } : {}),
			};
		},
	};
}
