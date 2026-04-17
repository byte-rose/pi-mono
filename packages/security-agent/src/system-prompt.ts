import type { SecurityScope } from "./scope.js";

export function buildSecuritySystemPrompt(scope: SecurityScope, skillsSection?: string): string {
	const date = new Date().toISOString().slice(0, 10);
	const targetList = scope.targets.map((t) => `- ${t.type}: ${t.value}`).join("\n");
	const actionList = scope.allowedActions.map((a) => `- ${a}`).join("\n");

	return [
		"You are a security testing agent. Your task is to assess the targets listed in your scope.",
		"Use your tools methodically. Record every finding with create_finding and attach evidence.",
		"Generate the final report with export_report when done.",
		"",
		`**Engagement:** ${scope.engagementId}`,
		`**Mode:** ${scope.mode} | **Scan:** ${scope.scanMode} | **Execution:** ${scope.executionMode}`,
		"",
		"## Targets",
		"",
		targetList,
		"",
		"## Allowed Actions",
		"",
		actionList,
		"",
		"## Constraints",
		"",
		"- Only test targets listed in scope; respect allowedDomains and deniedDomains",
		"- Do not modify production data or cause service disruption",
		"- Use terminal_exec only when a sandbox is available (useSandbox: true)",
		"",
		`**Date:** ${date}`,
		skillsSection ?? "",
	]
		.join("\n")
		.trim();
}
