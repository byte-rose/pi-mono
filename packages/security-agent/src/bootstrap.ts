// packages/security-agent/src/bootstrap.ts

import { mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { ArtifactStore } from "@byte-rose/nyati-security-artifacts";
import { DockerSecurityRuntime } from "@byte-rose/nyati-security-runtime";
import type { ExecFn } from "@byte-rose/nyati-security-tools";
import {
	attachEvidenceTool,
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
import { validateScope } from "./scope-validator.js";

export interface CreateSecuritySessionOptions {
	scope: SecurityScope;
	/** Override the run directory. Default: ~/.nyati/runs/<engagementId>/<timestamp> */
	runDir?: string;
	/** Whether to provision a Docker sandbox. Default: false */
	useSandbox?: boolean;
}

export interface SecuritySession {
	context: SecurityAgentContext;
	tools: ReturnType<typeof createSecurityTools>;
	cleanup(): Promise<void>;
}

function createSecurityTools(ctx: SecurityAgentContext, execFn: ExecFn | null) {
	return [
		// Reporting (no sandbox needed)
		createFindingTool(ctx.store),
		listFindingsTool(ctx.store),
		attachEvidenceTool(ctx.store),
		exportReportTool(ctx.store, ctx.scope.reporting.outputDir),
		// Runtime (null-safe when no sandbox)
		terminalExecTool(execFn, ctx.workspace),
		getScopeTool(ctx.scope),
		// Network (scope-enforced, uses native fetch)
		httpRequestTool(ctx.scope),
		// Scanners (null-safe when no sandbox)
		nucleiTool(execFn, ctx.workspace),
		semgrepTool(execFn, ctx.workspace),
		httpxTool(execFn, ctx.workspace),
	];
}

export async function createSecuritySession(options: CreateSecuritySessionOptions): Promise<SecuritySession> {
	const { scope, useSandbox = false } = options;

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

	const tools = createSecurityTools(context, execFn);

	return {
		context,
		tools,
		async cleanup() {
			if (runtime && context.workspace) {
				await runtime.destroyWorkspace(context.workspace.workspaceId);
				runtime.cleanup();
			}
		},
	};
}
