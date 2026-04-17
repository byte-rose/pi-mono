import type { Evidence, Finding } from "@byte-rose/nyati-security-artifacts";

export function renderFindingMd(finding: Finding): string {
	const lines: string[] = [
		`# ${finding.title}`,
		"",
		`**Severity:** ${finding.severity} | **Confidence:** ${finding.confidence} | **Status:** ${finding.status}`,
		"",
		`**Category:** ${finding.category}`,
	];
	if (finding.cwe) lines.push(`**CWE:** ${finding.cwe}`);
	if (finding.cve) lines.push(`**CVE:** ${finding.cve}`);
	if (finding.cvssScore !== undefined) lines.push(`**CVSS:** ${finding.cvssScore.toFixed(1)}`);
	if (finding.endpoint) lines.push(`**Endpoint:** \`${finding.endpoint}\``);
	lines.push("", "## Summary", "", finding.summary);
	lines.push("", "## Technical Analysis", "", finding.technicalAnalysis);
	lines.push("", "## Impact", "", finding.impact);
	lines.push("", "## Remediation", "", finding.remediation);
	return lines.join("\n");
}

export function renderFindingsTableMd(findings: Finding[]): string {
	if (findings.length === 0) return "_No findings._";
	const rows = findings.map((f) => `| ${f.severity} | ${f.title} | ${f.category} | ${f.status} |`);
	return ["| Severity | Title | Category | Status |", "|----------|-------|----------|--------|", ...rows].join("\n");
}

export function renderEvidenceMd(evidence: Evidence): string {
	const lines: string[] = [`## ${evidence.title}`, "", `**Type:** ${evidence.type}`];
	if (typeof evidence.content === "string") {
		lines.push("", "```", evidence.content, "```");
	} else {
		lines.push("", "```json", JSON.stringify(evidence.content, null, 2), "```");
	}
	return lines.join("\n");
}
