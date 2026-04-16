// packages/security-tools/src/reporting/list-findings.ts

import type { ArtifactStore } from "@byte-rose/nyati-security-artifacts";
import { type Static, Type } from "@sinclair/typebox";
import type { SecurityTool } from "../types.js";

const listFindingsSchema = Type.Object({
	severity: Type.Optional(
		Type.Union([
			Type.Literal("info"),
			Type.Literal("low"),
			Type.Literal("medium"),
			Type.Literal("high"),
			Type.Literal("critical"),
		]),
	),
	status: Type.Optional(
		Type.Union([
			Type.Literal("candidate"),
			Type.Literal("validated"),
			Type.Literal("reported"),
			Type.Literal("fixed"),
			Type.Literal("closed"),
		]),
	),
});

type ListFindingsInput = Static<typeof listFindingsSchema>;

export function listFindingsTool(store: ArtifactStore): SecurityTool<ListFindingsInput> {
	return {
		name: "list_findings",
		label: "List Findings",
		description: "List all security findings, optionally filtered by severity or status.",
		parameters: listFindingsSchema,
		async execute(input) {
			let findings = await store.listFindings();
			if (input.severity) findings = findings.filter((f) => f.severity === input.severity);
			if (input.status) findings = findings.filter((f) => f.status === input.status);
			return {
				success: true,
				findings: findings.map((f) => ({
					id: f.id,
					title: f.title,
					severity: f.severity,
					status: f.status,
					category: f.category,
					cvssScore: f.cvssScore,
				})),
				total: findings.length,
			};
		},
	};
}
