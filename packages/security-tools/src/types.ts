// packages/security-tools/src/types.ts

import type { ArtifactStore } from "@byte-rose/nyati-security-artifacts";
import type { ExecOptions, ExecResult, WorkspaceHandle } from "@byte-rose/nyati-security-runtime";
import type { TSchema } from "@sinclair/typebox";
import type { SecurityScope } from "./scope.js";

export type { ExecOptions, ExecResult, WorkspaceHandle } from "@byte-rose/nyati-security-runtime";

export type ExecFn = (workspaceId: string, command: string, options?: ExecOptions) => Promise<ExecResult>;

export interface SecurityAgentContext {
	store: ArtifactStore;
	scope: SecurityScope;
	runDir: string;
	workspace?: WorkspaceHandle;
}

/** Simplified tool descriptor — Bootstrap adapts this into a full pi AgentTool. */
export interface SecurityTool<TInput = unknown> {
	name: string;
	label: string;
	description: string;
	parameters: TSchema;
	execute(input: TInput): Promise<{ success: boolean; [key: string]: unknown }>;
}
