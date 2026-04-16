// packages/security-agent/src/context.ts
import type { ArtifactStore } from "@byte-rose/nyati-security-artifacts";
import type { WorkspaceHandle } from "@byte-rose/nyati-security-runtime";
import type { SecurityScope } from "./scope.js";

export interface SecurityAgentContext {
	scope: SecurityScope;
	store: ArtifactStore;
	workspace?: WorkspaceHandle;
	runDir: string;
}
