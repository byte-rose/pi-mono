// packages/security-tools/src/reporting/export-report.ts

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join } from "node:path";
import type { ArtifactStore } from "@byte-rose/nyati-security-artifacts";
import { exportJson, exportMarkdown } from "@byte-rose/nyati-security-reporting";
import { type Static, Type } from "@sinclair/typebox";
import type { SecurityTool } from "../types.js";

const exportReportSchema = Type.Object({
	format: Type.Union([Type.Literal("markdown"), Type.Literal("json")], {
		description: "Report format",
	}),
	outputPath: Type.Optional(Type.String({ description: "File path to write the report to" })),
});

type ExportReportInput = Static<typeof exportReportSchema>;

export function exportReportTool(store: ArtifactStore, defaultOutputDir: string): SecurityTool<ExportReportInput> {
	return {
		name: "export_report",
		label: "Export Report",
		description:
			"Export all findings as a markdown or JSON report. " +
			"Call this at the end of an assessment to produce the final deliverable.",
		parameters: exportReportSchema,
		async execute(input) {
			const findings = await store.listFindings();
			const evidence = await store.listEvidence();

			const content =
				input.format === "markdown" ? exportMarkdown(findings, evidence) : exportJson(findings, evidence);

			const ext = input.format === "markdown" ? "md" : "json";
			const filename = `report-${new Date().toISOString().slice(0, 10)}.${ext}`;
			const outputPath = input.outputPath ?? join(defaultOutputDir, filename);

			await mkdir(dirname(outputPath), { recursive: true });
			await writeFile(outputPath, content, "utf-8");

			return {
				success: true,
				outputPath,
				findingCount: findings.length,
				message: `Report exported to ${outputPath}`,
			};
		},
	};
}
