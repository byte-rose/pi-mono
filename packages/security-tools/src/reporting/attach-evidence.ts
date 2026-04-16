// packages/security-tools/src/reporting/attach-evidence.ts

import type { ArtifactStore } from "@byte-rose/nyati-security-artifacts";
import { type Static, Type } from "@sinclair/typebox";
import type { SecurityTool } from "../types.js";

const attachEvidenceSchema = Type.Object({
	findingId: Type.String({ description: "Finding ID to attach evidence to" }),
	title: Type.String({ description: "Short title for the evidence" }),
	type: Type.Union([
		Type.Literal("http"),
		Type.Literal("file"),
		Type.Literal("terminal"),
		Type.Literal("browser"),
		Type.Literal("note"),
		Type.Literal("diff"),
	]),
	content: Type.String({ description: "Evidence content (HTTP exchange, terminal output, file snippet, etc.)" }),
	targets: Type.Optional(Type.Array(Type.String())),
});

type AttachEvidenceInput = Static<typeof attachEvidenceSchema>;

export function attachEvidenceTool(store: ArtifactStore): SecurityTool<AttachEvidenceInput> {
	return {
		name: "attach_evidence",
		label: "Attach Evidence",
		description:
			"Attach evidence (HTTP exchange, terminal output, file snippet) to an existing finding. " +
			"Always include evidence for validated findings.",
		parameters: attachEvidenceSchema,
		async execute(input) {
			const finding = await store.getFinding(input.findingId);
			if (!finding) {
				return { success: false, error: `Finding '${input.findingId}' not found` };
			}

			const evidenceId = await store.appendEvidence({
				findingId: input.findingId,
				type: input.type,
				title: input.title,
				content: input.content,
				targets: input.targets ?? finding.targets,
			});

			await store.updateFinding(input.findingId, {
				evidenceIds: [...finding.evidenceIds, evidenceId],
				status: finding.status === "candidate" ? "validated" : finding.status,
			});

			return {
				success: true,
				evidenceId,
				message: `Evidence '${input.title}' attached to finding '${finding.title}'`,
			};
		},
	};
}
