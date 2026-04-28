// packages/security-agent/src/bootstrap.ts

import { appendFile, mkdir, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { ArtifactStore } from "@byte-rose/nyati-security-artifacts";
import type { SecurityRuntime } from "@byte-rose/nyati-security-runtime";
import { DockerSecurityRuntime } from "@byte-rose/nyati-security-runtime";
import { defaultSkillsDir, formatSkillsSection, loadSkillsForScope } from "@byte-rose/nyati-security-skills";
import type { AllowedAction, ExecFn, ScopeMutationEvent, SecurityTool } from "@byte-rose/nyati-security-tools";
import {
	addScopeTargetTool,
	attachEvidenceTool,
	browserActionTool,
	createFindingTool,
	exportReportTool,
	getScopeTool,
	httpRequestTool,
	httpxTool,
	listFindingsTool,
	nucleiTool,
	semgrepTool,
	terminalExecTool,
} from "@byte-rose/nyati-security-tools";
import type { SecurityAgentContext } from "./context.js";
import type { SecurityScope } from "./scope.js";
import { isActionAllowed, validateScope } from "./scope-validator.js";
import { buildSecuritySystemPrompt } from "./system-prompt.js";

export interface CreateSecuritySessionOptions {
	scope: SecurityScope;
	/** Override the run directory. Default: ~/.nyati/runs/<engagementId>/<timestamp> */
	runDir?: string;
	/** Whether to provision a Docker sandbox. Default: false */
	useSandbox?: boolean;
	/** Override the runtime implementation, primarily for tests. */
	runtime?: SecurityRuntime;
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

function requireAllowedActions<TInput>(
	scope: SecurityScope,
	tool: SecurityTool<TInput>,
	actions: AllowedAction[],
): SecurityTool<TInput> {
	if (actions.length === 0) {
		return tool;
	}

	return {
		...tool,
		async execute(input) {
			const missingActions = actions.filter((action) => !isActionAllowed(scope, action));
			if (missingActions.length > 0) {
				return {
					success: false,
					error: `Tool '${tool.name}' is outside scope. Missing allowedActions: ${missingActions.join(", ")}`,
				};
			}
			return tool.execute(input);
		},
	};
}

function getSandboxCapabilities(scope: SecurityScope): string[] {
	return isActionAllowed(scope, "network_scan") ? ["NET_RAW"] : [];
}

function createSecurityTools(
	ctx: SecurityAgentContext,
	execFn: ExecFn | null,
	options?: Pick<CreateSecuritySessionOptions, "agentBrowserBin" | "agentBrowserUseNpx" | "agentBrowserAutoInstall">,
	hooks?: { onScopeChanged?: (event: ScopeMutationEvent) => Promise<void> },
): SecurityTool<unknown>[] {
	const tools: SecurityTool<unknown>[] = [
		requireAllowedActions(ctx.scope, createFindingTool(ctx.store, ctx.scope), ["create_reports"]),
		requireAllowedActions(ctx.scope, listFindingsTool(ctx.store), ["create_reports"]),
		requireAllowedActions(ctx.scope, attachEvidenceTool(ctx.store, ctx.scope), ["create_reports"]),
		requireAllowedActions(ctx.scope, exportReportTool(ctx.store, ctx.scope.reporting.outputDir), ["create_reports"]),
		getScopeTool(ctx.scope),
		addScopeTargetTool(ctx.scope, { onScopeChanged: hooks?.onScopeChanged }),
		requireAllowedActions(
			ctx.scope,
			browserActionTool(ctx.scope, ctx.runDir, {
				agentBrowserBin: options?.agentBrowserBin,
				agentBrowserUseNpx: options?.agentBrowserUseNpx,
				agentBrowserAutoInstall: options?.agentBrowserAutoInstall,
			}),
			["browser_test"],
		),
		requireAllowedActions(ctx.scope, httpRequestTool(ctx.scope), ["http_test"]),
	];

	if (execFn && ctx.workspace) {
		tools.push(
			requireAllowedActions(ctx.scope, terminalExecTool(execFn, ctx.workspace), ["run_commands"]),
			requireAllowedActions(ctx.scope, nucleiTool(execFn, ctx.workspace, ctx.scope), [
				"run_commands",
				"network_scan",
			]),
			requireAllowedActions(ctx.scope, semgrepTool(execFn, ctx.workspace), ["read_files", "run_commands"]),
			requireAllowedActions(ctx.scope, httpxTool(execFn, ctx.workspace, ctx.scope), [
				"run_commands",
				"network_scan",
			]),
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

	let runtime: SecurityRuntime | undefined;
	let execFn: ExecFn | null = null;

	if (useSandbox) {
		runtime = options.runtime ?? new DockerSecurityRuntime();
		const workspace = await runtime.createWorkspace({
			agentId: scope.engagementId,
			capAdd: getSandboxCapabilities(scope),
		});
		context.workspace = workspace;
		await runtime.syncTargets(workspace.workspaceId, scope.targets);
		execFn = runtime.execInContainer.bind(runtime);
	}

	const skillCtx = {
		scanMode: scope.scanMode,
		executionMode: scope.executionMode,
		targetTypes: scope.targets.map((target) => target.type),
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
