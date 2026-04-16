// packages/security-tools/src/reporting/create-finding.ts

import type { ArtifactStore } from "@byte-rose/nyati-security-artifacts";
import { normalizeCve, normalizeCwe, validateFinding } from "@byte-rose/nyati-security-artifacts";
import { calculateCvss, validateCvssBreakdown } from "@byte-rose/nyati-security-reporting";
import { type Static, Type } from "@sinclair/typebox";
import type { SecurityTool } from "../types.js";

const CvssBreakdownSchema = Type.Object({
	attackVector: Type.Union([Type.Literal("N"), Type.Literal("A"), Type.Literal("L"), Type.Literal("P")]),
	attackComplexity: Type.Union([Type.Literal("L"), Type.Literal("H")]),
	privilegesRequired: Type.Union([Type.Literal("N"), Type.Literal("L"), Type.Literal("H")]),
	userInteraction: Type.Union([Type.Literal("N"), Type.Literal("R")]),
	scope: Type.Union([Type.Literal("U"), Type.Literal("C")]),
	confidentiality: Type.Union([Type.Literal("N"), Type.Literal("L"), Type.Literal("H")]),
	integrity: Type.Union([Type.Literal("N"), Type.Literal("L"), Type.Literal("H")]),
	availability: Type.Union([Type.Literal("N"), Type.Literal("L"), Type.Literal("H")]),
});

const createFindingSchema = Type.Object({
	title: Type.String({ description: "Short vulnerability title, e.g. 'Reflected XSS in search parameter'" }),
	category: Type.String({ description: "Vulnerability category, e.g. 'xss', 'sqli', 'idor'" }),
	summary: Type.String({ description: "One-paragraph summary of the vulnerability" }),
	technicalAnalysis: Type.String({ description: "Detailed technical analysis of the root cause" }),
	impact: Type.String({ description: "Business and technical impact" }),
	remediation: Type.String({ description: "Remediation guidance" }),
	cvssBreakdown: Type.Optional(CvssBreakdownSchema),
	endpoint: Type.Optional(Type.String({ description: "Affected endpoint URL" })),
	method: Type.Optional(Type.String({ description: "HTTP method" })),
	targets: Type.Optional(Type.Array(Type.String(), { description: "Target IDs or URLs" })),
	cwe: Type.Optional(Type.String({ description: "CWE identifier e.g. CWE-79" })),
	cve: Type.Optional(Type.String({ description: "CVE identifier e.g. CVE-2024-1234" })),
	confidence: Type.Optional(Type.Union([Type.Literal("low"), Type.Literal("medium"), Type.Literal("high")])),
});

type CreateFindingInput = Static<typeof createFindingSchema>;

export function createFindingTool(store: ArtifactStore): SecurityTool<CreateFindingInput> {
	return {
		name: "create_finding",
		label: "Create Finding",
		description:
			"Create a structured security finding with CVSS scoring. " +
			"Use this for every confirmed or candidate vulnerability. " +
			"Returns a finding ID for subsequent evidence attachment.",
		parameters: createFindingSchema,
		async execute(input) {
			const validationErrors = validateFinding({
				title: input.title,
				summary: input.summary,
				technicalAnalysis: input.technicalAnalysis,
				impact: input.impact,
				remediation: input.remediation,
			});
			if (validationErrors.length > 0) {
				return { success: false, errors: validationErrors };
			}

			const cve = input.cve ? normalizeCve(input.cve) : undefined;
			const cwe = input.cwe ? normalizeCwe(input.cwe) : undefined;

			let cvssScore: number | undefined;
			let cvssVector: string | undefined;
			let severity: "info" | "low" | "medium" | "high" | "critical" = "medium";

			if (input.cvssBreakdown) {
				const cvssErrors = validateCvssBreakdown(input.cvssBreakdown);
				if (cvssErrors.length > 0) {
					return { success: false, errors: cvssErrors };
				}
				const result = calculateCvss(input.cvssBreakdown);
				cvssScore = result.score;
				cvssVector = result.vector;
				severity = result.severity;
			}

			const id = await store.appendFinding({
				title: input.title,
				category: input.category,
				severity,
				confidence: input.confidence ?? "medium",
				status: "candidate",
				targets: input.targets ?? [],
				evidenceIds: [],
				summary: input.summary,
				technicalAnalysis: input.technicalAnalysis,
				impact: input.impact,
				remediation: input.remediation,
				cvssScore,
				cvssVector,
				cvssBreakdown: input.cvssBreakdown,
				endpoint: input.endpoint,
				method: input.method,
				...(cve ? { cve } : {}),
				...(cwe ? { cwe } : {}),
			});

			return {
				success: true,
				findingId: id,
				severity,
				cvssScore,
				message: `Finding '${input.title}' created (${severity}, id=${id.slice(0, 8)})`,
			};
		},
	};
}
