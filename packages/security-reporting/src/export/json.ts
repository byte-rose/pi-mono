import type { Evidence, Finding } from "@byte-rose/nyati-security-artifacts";

export interface JsonReport {
	generatedAt: string;
	findings: Finding[];
	evidence: Evidence[];
	summary: {
		total: number;
		bySeverity: Record<string, number>;
	};
}

export function exportJson(findings: Finding[], evidence: Evidence[]): string {
	const bySeverity: Record<string, number> = {};
	for (const f of findings) {
		bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
	}
	const report: JsonReport = {
		generatedAt: new Date().toISOString(),
		findings,
		evidence,
		summary: { total: findings.length, bySeverity },
	};
	return JSON.stringify(report, null, 2);
}
