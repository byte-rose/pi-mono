import { createRequire } from "node:module";
import type { CvssBreakdown, Severity } from "@byte-rose/nyati-security-artifacts";

// The cvss package is CJS; use createRequire to import it in ESM context
const require = createRequire(import.meta.url);
// eslint-disable-next-line @typescript-eslint/no-require-imports
const cvssLib = require("cvss") as {
	getBaseScore: (vector: string) => number;
	getRating: (score: number) => string;
};

const VALID_ATTACK_VECTOR = new Set(["N", "A", "L", "P"]);
const VALID_ATTACK_COMPLEXITY = new Set(["L", "H"]);
const VALID_PRIVILEGES_REQUIRED = new Set(["N", "L", "H"]);
const VALID_USER_INTERACTION = new Set(["N", "R"]);
const VALID_SCOPE = new Set(["U", "C"]);
const VALID_CIA = new Set(["N", "L", "H"]);

export function validateCvssBreakdown(breakdown: CvssBreakdown): string[] {
	const errors: string[] = [];

	if (!VALID_ATTACK_VECTOR.has(breakdown.attackVector)) {
		errors.push(`attackVector must be one of N, A, L, P but got "${breakdown.attackVector}"`);
	}
	if (!VALID_ATTACK_COMPLEXITY.has(breakdown.attackComplexity)) {
		errors.push(`attackComplexity must be one of L, H but got "${breakdown.attackComplexity}"`);
	}
	if (!VALID_PRIVILEGES_REQUIRED.has(breakdown.privilegesRequired)) {
		errors.push(`privilegesRequired must be one of N, L, H but got "${breakdown.privilegesRequired}"`);
	}
	if (!VALID_USER_INTERACTION.has(breakdown.userInteraction)) {
		errors.push(`userInteraction must be one of N, R but got "${breakdown.userInteraction}"`);
	}
	if (!VALID_SCOPE.has(breakdown.scope)) {
		errors.push(`scope must be one of U, C but got "${breakdown.scope}"`);
	}
	if (!VALID_CIA.has(breakdown.confidentiality)) {
		errors.push(`confidentiality must be one of N, L, H but got "${breakdown.confidentiality}"`);
	}
	if (!VALID_CIA.has(breakdown.integrity)) {
		errors.push(`integrity must be one of N, L, H but got "${breakdown.integrity}"`);
	}
	if (!VALID_CIA.has(breakdown.availability)) {
		errors.push(`availability must be one of N, L, H but got "${breakdown.availability}"`);
	}

	return errors;
}

function scoreToSeverity(score: number): Severity {
	if (score === 0) return "info";
	if (score < 4) return "low";
	if (score < 7) return "medium";
	if (score < 9) return "high";
	return "critical";
}

export function calculateCvss(breakdown: CvssBreakdown): { score: number; severity: Severity; vector: string } {
	const {
		attackVector,
		attackComplexity,
		privilegesRequired,
		userInteraction,
		scope,
		confidentiality,
		integrity,
		availability,
	} = breakdown;

	// Build the CVSS 3.1 vector string for output
	const vector = `CVSS:3.1/AV:${attackVector}/AC:${attackComplexity}/PR:${privilegesRequired}/UI:${userInteraction}/S:${scope}/C:${confidentiality}/I:${integrity}/A:${availability}`;

	// The cvss package only supports CVSS:3.0 prefix; use that for calculation
	const calcVector = `CVSS:3.0/AV:${attackVector}/AC:${attackComplexity}/PR:${privilegesRequired}/UI:${userInteraction}/S:${scope}/C:${confidentiality}/I:${integrity}/A:${availability}`;

	try {
		const score = cvssLib.getBaseScore(calcVector);
		const severity = scoreToSeverity(score);
		return { score, severity, vector };
	} catch {
		return { score: 7.5, severity: "high", vector };
	}
}
