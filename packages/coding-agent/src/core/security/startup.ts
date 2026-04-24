import { isAbsolute, resolve } from "node:path";
import { createSecuritySession } from "@byte-rose/nyati-security-agent";
import {
	deepWhiteboxAudit,
	quickBlackboxWebScan,
	standardBlackboxWebScan,
} from "@byte-rose/nyati-security-agent/presets";
import { httpRequestTool, type SecurityTool } from "@byte-rose/nyati-security-tools";
import type { Args } from "../../cli/args.js";
import type { AgentSessionRuntimeDiagnostic } from "../agent-session-services.js";
import { defineTool, type ExtensionAPI, type ToolDefinition } from "../extensions/index.js";

export type SecurityProfile = "quick" | "standard" | "deep";

interface RawSecurityStartupOptions {
	target?: string;
	profile?: string;
	engagementId?: string;
	workspacePath?: string;
	skillsDir?: string;
	agentBrowserBin?: string;
	agentBrowserUseNpx?: boolean;
	agentBrowserAutoInstall?: boolean;
	useSandbox?: boolean;
}

export interface ResolvedSecurityStartupOptions {
	target: string;
	profile: SecurityProfile;
	engagementId: string;
	workspacePath: string;
	skillsDir?: string;
	agentBrowserBin?: string;
	agentBrowserUseNpx?: boolean;
	agentBrowserAutoInstall: boolean;
	useSandbox: boolean;
}

export interface SecurityStartup {
	config: ResolvedSecurityStartupOptions;
	customTools: ToolDefinition[];
	systemPrompt: string;
	diagnostics: AgentSessionRuntimeDiagnostic[];
	cleanup(): Promise<void>;
}

const SECURITY_GUIDELINES = [
	"Respect the active security scope and stay within the configured targets.",
	"Use browser_action as the first-class interface for web exploration, rendering, auth flows, and screenshots in security mode.",
	"Record validated findings with create_finding, attach supporting evidence, and use export_report at the end.",
];

export const HTTP_REQUEST_BLOCK_MESSAGE =
	"http_request is deprecated in security mode. Use browser_action for all web workflows.";

let coreSecurityModeActive = false;

function getStringValue(value: string | undefined): string | undefined {
	if (typeof value !== "string") {
		return undefined;
	}

	const normalized = value.trim();
	return normalized.length > 0 ? normalized : undefined;
}

function parseBoolean(value: string | undefined): boolean | undefined {
	if (!value) {
		return undefined;
	}

	switch (value.trim().toLowerCase()) {
		case "1":
		case "true":
		case "yes":
		case "on":
			return true;
		case "0":
		case "false":
		case "no":
		case "off":
			return false;
		default:
			return undefined;
	}
}

function getEnvString(env: NodeJS.ProcessEnv, ...names: string[]): string | undefined {
	for (const name of names) {
		const value = getStringValue(env[name]);
		if (value) {
			return value;
		}
	}

	return undefined;
}

function getEnvBoolean(env: NodeJS.ProcessEnv, ...names: string[]): boolean | undefined {
	for (const name of names) {
		const parsed = parseBoolean(env[name]);
		if (parsed !== undefined) {
			return parsed;
		}
	}

	return undefined;
}

function normalizeBooleanFlag(value: boolean | string | undefined): boolean | undefined {
	if (typeof value === "boolean") {
		return value;
	}
	if (typeof value === "string") {
		return parseBoolean(value);
	}
	return undefined;
}

function resolveProfile(value: string | undefined): SecurityProfile {
	switch (value) {
		case "quick":
		case "standard":
		case "deep":
			return value;
		default:
			return "standard";
	}
}

function sanitizeEngagementId(value: string): string {
	const normalized = value.trim().replace(/[^A-Za-z0-9._-]+/g, "-");
	const collapsed = normalized.replace(/^-+/, "").replace(/-+$/, "");
	return collapsed.length > 0 ? collapsed : `security-${Date.now()}`;
}

function resolvePathFromCwd(cwd: string, path: string | undefined): string | undefined {
	if (!path) {
		return undefined;
	}

	return isAbsolute(path) ? path : resolve(cwd, path);
}

function getFlagString(pi: ExtensionAPI, name: string): string | undefined {
	const value = pi.getFlag(name);
	return typeof value === "string" ? getStringValue(value) : undefined;
}

function createSecurityScope(config: ResolvedSecurityStartupOptions) {
	switch (config.profile) {
		case "quick":
			return quickBlackboxWebScan(config.target, config.engagementId);
		case "deep":
			return deepWhiteboxAudit(config.target, config.engagementId, config.workspacePath);
		default:
			return standardBlackboxWebScan(config.target, config.engagementId);
	}
}

function formatSecurityResult(toolName: string, result: { success: boolean; [key: string]: unknown }): string {
	if (toolName === "browser_action") {
		const stdout = typeof result.stdout === "string" ? result.stdout.trim() : "";
		const stderr = typeof result.stderr === "string" ? result.stderr.trim() : "";
		if (stdout.length > 0 && stderr.length === 0) {
			return stdout;
		}
	}

	try {
		return JSON.stringify(result, null, 2);
	} catch {
		return String(result);
	}
}

function wrapSecurityTool<TInput>(tool: SecurityTool<TInput>) {
	return defineTool({
		name: tool.name,
		label: tool.label,
		description: tool.description,
		promptSnippet: tool.description,
		promptGuidelines: SECURITY_GUIDELINES,
		parameters: tool.parameters,
		async execute(_toolCallId, params) {
			const result = await tool.execute(params as TInput);
			return {
				content: [{ type: "text", text: formatSecurityResult(tool.name, result) }],
				details: result,
				isError: result.success === false,
			};
		},
	});
}

function createBlockedHttpRequestTool(config: ResolvedSecurityStartupOptions): ToolDefinition {
	const scope = createSecurityScope(config);
	const blockedTool = httpRequestTool(scope);

	return defineTool({
		name: blockedTool.name,
		label: blockedTool.label,
		description: blockedTool.description,
		parameters: blockedTool.parameters,
		async execute() {
			return {
				content: [{ type: "text", text: HTTP_REQUEST_BLOCK_MESSAGE }],
				details: {
					blocked: true,
					reason: HTTP_REQUEST_BLOCK_MESSAGE,
				},
				isError: true,
			};
		},
	});
}

export function formatSecurityStatus(config: Pick<ResolvedSecurityStartupOptions, "profile" | "useSandbox">): string {
	return `sec:${config.profile}${config.useSandbox ? "+sandbox" : ""}`;
}

export function isCoreSecurityModeActive(): boolean {
	return coreSecurityModeActive;
}

export function resolveSecurityStartupOptions(
	raw: RawSecurityStartupOptions,
	cwd: string,
	env: NodeJS.ProcessEnv = process.env,
): ResolvedSecurityStartupOptions | undefined {
	const target = getStringValue(raw.target) ?? getEnvString(env, "PI_SECURITY_TARGET", "NYATI_SECURITY_TARGET");
	if (!target) {
		return undefined;
	}

	const profile = resolveProfile(
		getStringValue(raw.profile) ?? getEnvString(env, "PI_SECURITY_PROFILE", "NYATI_SECURITY_PROFILE"),
	);
	const engagementId = sanitizeEngagementId(
		getStringValue(raw.engagementId) ??
			getEnvString(
				env,
				"PI_SECURITY_ENGAGEMENT",
				"PI_SECURITY_ENGAGEMENT_ID",
				"NYATI_SECURITY_ENGAGEMENT",
				"NYATI_SECURITY_ENGAGEMENT_ID",
			) ??
			`security-${profile}-${Date.now()}`,
	);
	const workspacePath =
		resolvePathFromCwd(
			cwd,
			getStringValue(raw.workspacePath) ?? getEnvString(env, "PI_SECURITY_WORKSPACE", "NYATI_SECURITY_WORKSPACE"),
		) ?? cwd;
	const skillsDir = resolvePathFromCwd(
		cwd,
		getStringValue(raw.skillsDir) ?? getEnvString(env, "PI_SECURITY_SKILLS_DIR", "NYATI_SECURITY_SKILLS_DIR"),
	);
	const agentBrowserBin =
		getStringValue(raw.agentBrowserBin) ?? getEnvString(env, "PI_AGENT_BROWSER_BIN", "NYATI_AGENT_BROWSER_BIN");
	const agentBrowserUseNpx =
		raw.agentBrowserUseNpx ?? getEnvBoolean(env, "PI_AGENT_BROWSER_USE_NPX", "NYATI_AGENT_BROWSER_USE_NPX");
	const agentBrowserAutoInstall =
		raw.agentBrowserAutoInstall ??
		getEnvBoolean(env, "PI_AGENT_BROWSER_AUTO_INSTALL", "NYATI_AGENT_BROWSER_AUTO_INSTALL") ??
		true;
	const useSandbox = raw.useSandbox ?? getEnvBoolean(env, "PI_SECURITY_SANDBOX", "NYATI_SECURITY_SANDBOX") ?? false;

	return {
		target,
		profile,
		engagementId,
		workspacePath,
		skillsDir,
		agentBrowserBin,
		agentBrowserUseNpx,
		agentBrowserAutoInstall,
		useSandbox,
	};
}

export function resolveSecurityStartupOptionsFromArgs(
	parsed: Args,
	cwd: string,
	env: NodeJS.ProcessEnv = process.env,
): ResolvedSecurityStartupOptions | undefined {
	return resolveSecurityStartupOptions(
		{
			target: parsed.securityTarget,
			profile: parsed.securityProfile,
			engagementId: parsed.securityEngagement,
			workspacePath: parsed.securityWorkspace,
			skillsDir: parsed.securitySkillsDir,
			agentBrowserBin: parsed.securityBrowserBin,
			agentBrowserUseNpx: normalizeBooleanFlag(parsed.unknownFlags.get("security-browser-use-npx")),
			agentBrowserAutoInstall: parsed.securityBrowserAutoInstall,
			useSandbox: parsed.securitySandbox,
		},
		cwd,
		env,
	);
}

export function resolveSecurityStartupOptionsFromExtension(
	pi: ExtensionAPI,
	cwd: string,
	env: NodeJS.ProcessEnv = process.env,
): ResolvedSecurityStartupOptions | undefined {
	return resolveSecurityStartupOptions(
		{
			target: getFlagString(pi, "security-target"),
			profile: getFlagString(pi, "security-profile"),
			engagementId: getFlagString(pi, "security-engagement"),
			workspacePath: getFlagString(pi, "security-workspace"),
			skillsDir: getFlagString(pi, "security-skills-dir"),
			agentBrowserBin: getFlagString(pi, "security-browser-bin"),
			agentBrowserUseNpx: normalizeBooleanFlag(pi.getFlag("security-browser-use-npx")),
			agentBrowserAutoInstall: normalizeBooleanFlag(pi.getFlag("security-browser-auto-install")),
			useSandbox: normalizeBooleanFlag(pi.getFlag("security-sandbox")),
		},
		cwd,
		env,
	);
}

export async function createSecurityStartup(
	config: ResolvedSecurityStartupOptions,
	options?: { runDir?: string },
): Promise<SecurityStartup> {
	const securitySession = await createSecuritySession({
		scope: createSecurityScope(config),
		runDir: options?.runDir,
		useSandbox: config.useSandbox,
		skillsDir: config.skillsDir,
		agentBrowserBin: config.agentBrowserBin,
		agentBrowserUseNpx: config.agentBrowserUseNpx,
		agentBrowserAutoInstall: config.agentBrowserAutoInstall,
	});

	coreSecurityModeActive = true;
	let cleanedUp = false;

	return {
		config,
		customTools: [
			...securitySession.tools.map((tool) => wrapSecurityTool(tool as SecurityTool<unknown>)),
			createBlockedHttpRequestTool(config),
		],
		systemPrompt: securitySession.systemPrompt,
		diagnostics: [
			{
				type: "info",
				message: `Security mode enabled: ${formatSecurityStatus(config)} (${config.target})`,
			},
		],
		async cleanup() {
			if (cleanedUp) {
				return;
			}

			cleanedUp = true;
			coreSecurityModeActive = false;
			await securitySession.cleanup();
		},
	};
}

async function cleanupSecurityStartup(startup: SecurityStartup | undefined): Promise<void> {
	if (startup) {
		await startup.cleanup();
	}
}

export default function securityPiCompatibilityExtension(pi: ExtensionAPI) {
	let securityStartup: SecurityStartup | undefined;
	let setupError: string | undefined;

	pi.registerFlag("security-target", {
		description: "Security target URL. Enables the bundled security tools when set.",
		type: "string",
	});
	pi.registerFlag("security-profile", {
		description: "Security profile: quick, standard, or deep. Defaults to standard.",
		type: "string",
	});
	pi.registerFlag("security-engagement", {
		description: "Engagement identifier used for nyati run directories and reports.",
		type: "string",
	});
	pi.registerFlag("security-workspace", {
		description: "Workspace path for deep profile local-code scope. Defaults to the session cwd.",
		type: "string",
	});
	pi.registerFlag("security-skills-dir", {
		description: "Optional custom security skills directory.",
		type: "string",
	});
	pi.registerFlag("security-browser-bin", {
		description: "Optional path to the local agent-browser binary.",
		type: "string",
	});
	pi.registerFlag("security-browser-use-npx", {
		description: "Legacy compatibility mode: use `npx agent-browser` instead of the packaged CLI.",
		type: "boolean",
	});
	pi.registerFlag("security-browser-auto-install", {
		description: "Automatically provision the Agent Browser runtime when missing. Defaults to true.",
		type: "boolean",
	});
	pi.registerFlag("security-sandbox", {
		description: "Provision the Docker-backed security sandbox runtime.",
		type: "boolean",
	});

	pi.on("session_start", async (_event, ctx) => {
		setupError = undefined;
		ctx.ui.setStatus("security", undefined);

		await cleanupSecurityStartup(securityStartup);
		securityStartup = undefined;

		if (isCoreSecurityModeActive()) {
			return;
		}

		const config = resolveSecurityStartupOptionsFromExtension(pi, ctx.cwd);
		if (!config) {
			return;
		}

		try {
			securityStartup = await createSecurityStartup(config);
			for (const tool of securityStartup.customTools) {
				pi.registerTool(tool);
			}

			ctx.ui.setStatus("security", formatSecurityStatus(config));
		} catch (error) {
			setupError = error instanceof Error ? error.message : String(error);
			ctx.ui.setStatus("security", "sec:error");
			if (ctx.hasUI) {
				ctx.ui.notify(`Security setup failed: ${setupError}`, "error");
			}
		}
	});

	pi.on("before_agent_start", async (event) => {
		if (setupError || !securityStartup) {
			return;
		}

		return {
			systemPrompt: `${event.systemPrompt}\n\n${securityStartup.systemPrompt}`,
		};
	});

	pi.on("session_shutdown", async (_event, ctx) => {
		ctx.ui.setStatus("security", undefined);
		await cleanupSecurityStartup(securityStartup);
		securityStartup = undefined;
		setupError = undefined;
	});
}
