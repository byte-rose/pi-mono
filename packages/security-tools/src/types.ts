// packages/security-tools/src/types.ts

import type { SecurityScope } from "@byte-rose/nyati-security-agent";
import type { ArtifactStore } from "@byte-rose/nyati-security-artifacts";
import type { TSchema } from "@sinclair/typebox";

export interface SecurityAgentContext {
	store: ArtifactStore;
	scope: SecurityScope;
	runDir: string;
}

/** Simplified tool descriptor — Bootstrap adapts this into a full pi AgentTool. */
export interface SecurityTool<TInput = unknown> {
	name: string;
	label: string;
	description: string;
	parameters: TSchema;
	execute(input: TInput): Promise<{ success: boolean; [key: string]: unknown }>;
}
