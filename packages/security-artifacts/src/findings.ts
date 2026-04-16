interface FindingRequiredFields {
	title: string;
	summary: string;
	technicalAnalysis: string;
	impact: string;
	remediation: string;
}

/** Returns array of validation error strings (empty = valid). */
export function validateFinding(fields: FindingRequiredFields): string[] {
	const errors: string[] = [];
	const required: (keyof FindingRequiredFields)[] = ["title", "summary", "technicalAnalysis", "impact", "remediation"];
	for (const field of required) {
		if (!fields[field]?.trim()) {
			errors.push(`${field} cannot be empty`);
		}
	}
	return errors;
}

/** Extract canonical CVE-YYYY-NNNNN. Returns null if not found/invalid. */
export function normalizeCve(raw: string): string | null {
	const match = /CVE-\d{4}-\d{4,}/.exec(raw);
	return match ? match[0] : null;
}

/** Extract canonical CWE-NNN. Returns null if not found/invalid. */
export function normalizeCwe(raw: string): string | null {
	const match = /CWE-\d+/.exec(raw);
	return match ? match[0] : null;
}

/**
 * Title-based duplicate detection.
 * Returns ID of the first potential duplicate, or null.
 * Two findings are duplicates if:
 * - exact title match (case-insensitive), OR
 * - same endpoint AND >80% word overlap in titles
 */
export function findDuplicate(
	candidate: { title: string; endpoint?: string },
	existing: Array<{ id: string; title: string; endpoint?: string }>,
): string | null {
	const candidateTitle = candidate.title.toLowerCase().trim();
	for (const e of existing) {
		const existingTitle = e.title.toLowerCase().trim();
		if (existingTitle === candidateTitle) return e.id;
		if (candidate.endpoint && candidate.endpoint === e.endpoint) {
			const words1 = new Set(candidateTitle.split(/\s+/));
			const words2 = existingTitle.split(/\s+/);
			const shared = words2.filter((w) => words1.has(w)).length;
			if (shared / Math.max(words1.size, words2.length) > 0.8) return e.id;
		}
	}
	return null;
}
