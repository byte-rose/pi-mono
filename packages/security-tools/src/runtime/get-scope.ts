// packages/security-tools/src/runtime/get-scope.ts

import { Type } from "@sinclair/typebox";
import type { SecurityScope } from "../scope.js";
import type { SecurityTool } from "../types.js";

const getScopeSchema = Type.Object({});

export function getScopeTool(scope: SecurityScope): SecurityTool<Record<string, never>> {
	return {
		name: "get_scope",
		label: "Get Scope",
		description:
			"Return the full engagement scope: targets, allowed actions, network policy, and filesystem policy. " +
			"Call this at the start of a session to understand what you are authorised to test.",
		parameters: getScopeSchema,
		async execute(_input) {
			return {
				success: true,
				engagementId: scope.engagementId,
				mode: scope.mode,
				scanMode: scope.scanMode,
				executionMode: scope.executionMode,
				targets: scope.targets,
				allowedActions: scope.allowedActions,
				network: scope.network,
				filesystem: scope.filesystem,
			};
		},
	};
}
