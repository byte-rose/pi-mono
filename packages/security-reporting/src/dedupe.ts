import type { Finding } from "@byte-rose/nyati-security-artifacts";

export function dedupeFindings(findings: Finding[]): Finding[] {
	const seen = new Set<string>();
	return findings.filter((f) => {
		const key = `${f.title.toLowerCase().trim()}::${f.endpoint ?? ""}`;
		if (seen.has(key)) return false;
		seen.add(key);
		return true;
	});
}
