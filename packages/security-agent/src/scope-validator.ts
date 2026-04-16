// packages/security-agent/src/scope-validator.ts
import type { SecurityScope } from "./scope.js";

const VALID_MODES = ["blackbox", "whitebox", "hybrid"] as const;
const VALID_SCAN_MODES = ["quick", "standard", "deep"] as const;
const VALID_EXECUTION_MODES = ["read_only", "validate", "exploit", "remediate"] as const;

export function validateScope(scope: SecurityScope): string[] {
	const errors: string[] = [];

	if (!scope.engagementId?.trim()) errors.push("engagementId cannot be empty");
	if (!VALID_MODES.includes(scope.mode)) errors.push(`mode must be one of: ${VALID_MODES.join(", ")}`);
	if (!VALID_SCAN_MODES.includes(scope.scanMode))
		errors.push(`scanMode must be one of: ${VALID_SCAN_MODES.join(", ")}`);
	if (!VALID_EXECUTION_MODES.includes(scope.executionMode))
		errors.push(`executionMode must be one of: ${VALID_EXECUTION_MODES.join(", ")}`);
	if (!scope.targets || scope.targets.length === 0) errors.push("scope must have at least one target");
	if (!scope.filesystem.artifactDir?.trim()) errors.push("filesystem.artifactDir cannot be empty");
	if (!scope.reporting.outputDir?.trim()) errors.push("reporting.outputDir cannot be empty");

	for (const [i, target] of scope.targets.entries()) {
		if (!target.value?.trim()) errors.push(`targets[${i}].value cannot be empty`);
		if (!target.id?.trim()) errors.push(`targets[${i}].id cannot be empty`);
	}

	return errors;
}

/** Check if an action is permitted by the current scope. */
export function isActionAllowed(scope: SecurityScope, action: string): boolean {
	return scope.allowedActions.includes(action as SecurityScope["allowedActions"][number]);
}

/** Check if a domain is within network policy. */
export function isDomainAllowed(scope: SecurityScope, domain: string): boolean {
	if (scope.network.deniedDomains.some((d) => domain.endsWith(d))) return false;
	if (scope.network.allowedDomains.length === 0) return true;
	return scope.network.allowedDomains.some((d) => domain.endsWith(d));
}
