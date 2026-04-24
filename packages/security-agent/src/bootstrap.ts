// packages/security-agent/src/bootstrap.ts

import { mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { ArtifactStore } from "@byte-rose/nyati-security-artifacts";
import { DockerSecurityRuntime } from "@byte-rose/nyati-security-runtime";
import { defaultSkillsDir, formatSkillsSection, loadSkillsForScope } from "@byte-rose/nyati-security-skills";
import type { ExecFn, SecurityTool } from "@byte-rose/nyati-security-tools";
import {
	attachEvidenceTool,
	browserActionTool,
	createFindingTool,
	exportReportTool,
	getScopeTool,
	httpxTool,
	listFindingsTool,
	nucleiTool,
	semgrepTool,
	terminalExecTool,
} from "@byte-rose/nyati-security-tools";
import type { SecurityAgentContext } from "./context.js";
import type { SecurityScope } from "./scope.js";
import { validateScope } from "./scope-validator.js";
import { buildSecuritySystemPrompt } from "./system-prompt.js";

export interface CreateSecuritySessionOptions {
	scope: SecurityScope;
	/** Override the run directory. Default: ~/.nyati/runs/<engagementId>/<timestamp> */
	runDir?: string;
	/** Whether to provision a Docker sandbox. Default: false */
	useSandbox?: boolean;
	/**
	 * Directory containing SKILL.md files. Default: the built-in skills bundled with
	 * @byte-rose/nyati-security-skills. Pass `null` to disable skill injection.
	 */
	skillsDir?: string | null;
	/** Optional override for the local agent-browser binary path. */
	agentBrowserBin?: string;
	/** Use `npx agent-browser` instead of a directly installed binary. */
	agentBrowserUseNpx?: boolean;
	/** Automatically install the Agent Browser CLI when missing. Default: true */
	agentBrowserAutoInstall?: boolean;
}

export interface SecuritySession {
	context: SecurityAgentContext;
	tools: ReturnType<typeof createSecurityTools>;
	systemPrompt: string;
	cleanup(): Promise<void>;
}

function createSecurityTools(
	ctx: SecurityAgentContext,
	execFn: ExecFn | null,
	options?: Pick<CreateSecuritySessionOptions, "agentBrowserBin" | "agentBrowserUseNpx" | "agentBrowserAutoInstall">,
): SecurityTool<unknown>[] {
	const tools: SecurityTool<unknown>[] = [
		// Reporting (no sandbox needed)
		createFindingTool(ctx.store),
		listFindingsTool(ctx.store),
		attachEvidenceTool(ctx.store),
		exportReportTool(ctx.store, ctx.scope.reporting.outputDir),
		getScopeTool(ctx.scope),
		// Browser (first-class web workflow)
		browserActionTool(ctx.scope, ctx.runDir, {
			agentBrowserBin: options?.agentBrowserBin,
			agentBrowserUseNpx: options?.agentBrowserUseNpx,
			agentBrowserAutoInstall: options?.agentBrowserAutoInstall,
		}),
	];

	if (execFn && ctx.workspace) {
		tools.push(
			terminalExecTool(execFn, ctx.workspace),
			nucleiTool(execFn, ctx.workspace),
			semgrepTool(execFn, ctx.workspace),
			httpxTool(execFn, ctx.workspace),
		);
	}

	return tools;
}

export async function createSecuritySession(options: CreateSecuritySessionOptions): Promise<SecuritySession> {
	const { scope, useSandbox = false, skillsDir = defaultSkillsDir } = options;

	const errors = validateScope(scope);
	if (errors.length > 0) {
		throw new Error(`Invalid scope:\n${errors.map((e) => `  - ${e}`).join("\n")}`);
	}

	const runDir = options.runDir ?? join(homedir(), ".nyati", "runs", scope.engagementId, String(Date.now()));
	await mkdir(runDir, { recursive: true });
	await mkdir(scope.reporting.outputDir, { recursive: true });

	const store = new ArtifactStore(runDir);
	const context: SecurityAgentContext = { scope, store, runDir };

	let runtime: DockerSecurityRuntime | undefined;
	let execFn: ExecFn | null = null;

	if (useSandbox) {
		runtime = new DockerSecurityRuntime();
		const workspace = await runtime.createWorkspace({ agentId: scope.engagementId });
		context.workspace = workspace;
		execFn = runtime.execInContainer.bind(runtime);
	}

	const skillCtx = {
		scanMode: scope.scanMode,
		executionMode: scope.executionMode,
		targetTypes: scope.targets.map((t) => t.type),
	};
	const skills = skillsDir ? loadSkillsForScope(skillCtx, skillsDir) : [];
	const systemPrompt = buildSecuritySystemPrompt(scope, formatSkillsSection(skills));

	const tools = createSecurityTools(context, execFn, options);

	return {
		context,
		tools,
		systemPrompt,
		async cleanup() {
			if (runtime && context.workspace) {
				await runtime.destroyWorkspace(context.workspace.workspaceId);
				runtime.cleanup();
			}
		},
	};
}
