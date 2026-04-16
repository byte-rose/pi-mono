// packages/security-agent/src/bootstrap.ts

import { mkdir } from "node:fs/promises";
import { homedir } from "node:os";
import { join } from "node:path";
import { ArtifactStore } from "@byte-rose/nyati-security-artifacts";
import { DockerSecurityRuntime } from "@byte-rose/nyati-security-runtime";
import {
	attachEvidenceTool,
	createFindingTool,
	exportReportTool,
	listFindingsTool,
} from "@byte-rose/nyati-security-tools";
import type { SecurityAgentContext } from "./context.js";
import type { SecurityScope } from "./scope.js";
import { validateScope } from "./scope-validator.js";

export interface CreateSecuritySessionOptions {
	scope: SecurityScope;
	/** Override the run directory. Default: ~/.nyati/runs/<engagementId>/<timestamp> */
	runDir?: string;
	/** Whether to provision a Docker sandbox. Default: false for Phase 1 */
	useSandbox?: boolean;
}

export interface SecuritySession {
	context: SecurityAgentContext;
	tools: ReturnType<typeof createSecurityTools>;
	cleanup(): Promise<void>;
}

function createSecurityTools(ctx: SecurityAgentContext) {
	return [
		createFindingTool(ctx.store),
		listFindingsTool(ctx.store),
		attachEvidenceTool(ctx.store),
		exportReportTool(ctx.store, ctx.scope.reporting.outputDir),
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
	if (useSandbox) {
		runtime = new DockerSecurityRuntime();
		const workspace = await runtime.createWorkspace({ agentId: scope.engagementId });
		context.workspace = workspace;
	}

	const tools = createSecurityTools(context);

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
