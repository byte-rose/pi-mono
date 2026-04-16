import type { Evidence, Finding } from "@byte-rose/nyati-security-artifacts";

const SEVERITY_BADGE: Record<string, string> = {
	critical: "[CRITICAL]",
	high: "[HIGH]",
	medium: "[MEDIUM]",
	low: "[LOW]",
	info: "[INFO]",
};

export function exportMarkdown(findings: Finding[], evidence: Evidence[]): string {
	const lines: string[] = [
		"# Security Assessment Report",
		"",
		`**Generated:** ${new Date().toISOString()}`,
		`**Total Findings:** ${findings.length}`,
		"",
		"---",
		"",
	];

	const bySeverity = ["critical", "high", "medium", "low", "info"];
	const counts = bySeverity
		.map((s) => `${s}: ${findings.filter((f) => f.severity === s).length}`)
		.filter((s) => !s.endsWith(": 0"))
		.join(" | ");
	if (counts) {
		lines.push(`**Severity Summary:** ${counts}`, "", "---", "");
	}

	for (const f of findings) {
		const badge = SEVERITY_BADGE[f.severity] ?? `[${f.severity.toUpperCase()}]`;
		lines.push(`## ${badge} ${f.title}`, "");
		lines.push(`**Severity:** ${f.severity} | **Confidence:** ${f.confidence} | **Status:** ${f.status}`);
		if (f.cvssScore !== undefined) lines.push(`**CVSS Score:** ${f.cvssScore}`);
		if (f.cwe) lines.push(`**CWE:** ${f.cwe}`);
		if (f.cve) lines.push(`**CVE:** ${f.cve}`);
		if (f.endpoint) lines.push(`**Endpoint:** \`${f.method ?? "GET"} ${f.endpoint}\``);
		lines.push("", "### Summary", f.summary, "");
		lines.push("### Technical Analysis", f.technicalAnalysis, "");
		lines.push("### Impact", f.impact, "");
		lines.push("### Remediation", f.remediation, "");

		const related = evidence.filter((e) => f.evidenceIds.includes(e.id));
		if (related.length > 0) {
			lines.push("### Evidence");
			for (const e of related) lines.push(`- **${e.title}** (${e.type})`);
			lines.push("");
		}
		lines.push("---", "");
	}

	return lines.join("\n");
}
