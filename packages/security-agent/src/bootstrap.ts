// packages/security-agent/src/bootstrap.ts

import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { ArtifactStore } from "@byte-rose/nyati-security-artifacts";
import { DockerSecurityRuntime } from "@byte-rose/nyati-security-runtime";
import { defaultSkillsDir, formatSkillsSection, loadSkillsForScope } from "@byte-rose/nyati-security-skills";
import type { ExecFn, ScopeMutationEvent, SecurityTool } from "@byte-rose/nyati-security-tools";
import {
	addScopeTargetTool,
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
	buildSystemPrompt(): string;
	cleanup(): Promise<void>;
}

function createSecurityTools(
	ctx: SecurityAgentContext,
	execFn: ExecFn | null,
	options?: Pick<CreateSecuritySessionOptions, "agentBrowserBin" | "agentBrowserUseNpx" | "agentBrowserAutoInstall">,
	hooks?: { onScopeChanged?: (event: ScopeMutationEvent) => Promise<void> },
): SecurityTool<unknown>[] {
	const tools: SecurityTool<unknown>[] = [
		// Reporting (no sandbox needed)
		createFindingTool(ctx.store, ctx.scope),
		listFindingsTool(ctx.store),
		attachEvidenceTool(ctx.store, ctx.scope),
		exportReportTool(ctx.store, ctx.scope.reporting.outputDir),
		getScopeTool(ctx.scope),
		addScopeTargetTool(ctx.scope, { onScopeChanged: hooks?.onScopeChanged }),
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
			nucleiTool(execFn, ctx.workspace, ctx.scope),
			semgrepTool(execFn, ctx.workspace),
			httpxTool(execFn, ctx.workspace, ctx.scope),
		);
	}

	return tools;
}

async function writeScopeSnapshot(runDir: string, scope: SecurityScope): Promise<void> {
	await writeFile(join(runDir, "scope.json"), JSON.stringify(scope, null, 2), "utf-8");
}

async function appendScopeEvent(runDir: string, event: ScopeMutationEvent): Promise<void> {
	await appendFile(join(runDir, "scope-events.jsonl"), `${JSON.stringify(event)}\n`, "utf-8");
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
	await writeScopeSnapshot(runDir, scope);

	const store = new ArtifactStore(runDir);
	const context: SecurityAgentContext = { scope, store, runDir };

	let runtime: DockerSecurityRuntime | undefined;
	let execFn: ExecFn | null = null;

	if (useSandbox) {
		runtime = new DockerSecurityRuntime();
		const workspace = await runtime.createWorkspace({ agentId: scope.engagementId });
		context.workspace = workspace;
		execFn = runtime.execInContainer.bind(runtime);
		await runtime.syncTargets(workspace.workspaceId, scope.targets);
	}

	const skillCtx = {
		scanMode: scope.scanMode,
		executionMode: scope.executionMode,
		targetTypes: scope.targets.map((t) => t.type),
	};
	const skills = skillsDir ? loadSkillsForScope(skillCtx, skillsDir) : [];
	const skillsSection = formatSkillsSection(skills);
	const buildSystemPrompt = () => buildSecuritySystemPrompt(scope, skillsSection);
	const systemPrompt = buildSystemPrompt();

	const onScopeChanged = async (event: ScopeMutationEvent) => {
		await writeScopeSnapshot(runDir, scope);
		await appendScopeEvent(runDir, event);
		if (runtime && context.workspace) {
			await runtime.syncTargets(context.workspace.workspaceId, scope.targets);
		}
	};

	const tools = createSecurityTools(context, execFn, options, { onScopeChanged });

	return {
		context,
		tools,
		systemPrompt,
		buildSystemPrompt,
		async cleanup() {
			if (runtime && context.workspace) {
				await runtime.destroyWorkspace(context.workspace.workspaceId);
				runtime.cleanup();
			}
		},
	};
}
