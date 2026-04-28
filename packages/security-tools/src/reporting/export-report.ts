// packages/security-tools/src/reporting/export-report.ts

import { mkdir, writeFile } from "node:fs/promises";
import { dirname, isAbsolute, join, relative, resolve } from "node:path";
import type { ArtifactStore } from "@byte-rose/nyati-security-artifacts";
import { exportJson, exportMarkdown } from "@byte-rose/nyati-security-reporting";
import { type Static, Type } from "@sinclair/typebox";
import type { SecurityTool } from "../types.js";

const exportReportSchema = Type.Object({
	format: Type.Union([Type.Literal("markdown"), Type.Literal("json")], {
		description: "Report format",
	}),
	outputPath: Type.Optional(Type.String({ description: "Path to write inside the report output directory" })),
});

type ExportReportInput = Static<typeof exportReportSchema>;

function resolveOutputPath(
	defaultOutputDir: string,
	outputPath: string | undefined,
	format: "markdown" | "json",
): string | null {
	const ext = format === "markdown" ? "md" : "json";
	const filename = `report-${new Date().toISOString().slice(0, 10)}.${ext}`;
	const baseDir = resolve(defaultOutputDir);
	const candidate = outputPath
		? resolve(isAbsolute(outputPath) ? outputPath : join(baseDir, outputPath))
		: resolve(join(baseDir, filename));
	const relativePath = relative(baseDir, candidate);

	if (relativePath === "" || (!relativePath.startsWith("..") && !isAbsolute(relativePath))) {
		return candidate;
	}

	return null;
}

export function exportReportTool(store: ArtifactStore, defaultOutputDir: string): SecurityTool<ExportReportInput> {
	return {
		name: "export_report",
		label: "Export Report",
		description:
			"Export all findings as a markdown or JSON report. " +
			"Call this at the end of an assessment to produce the final deliverable. " +
			"Writes are restricted to the configured reporting output directory.",
		parameters: exportReportSchema,
		async execute(input) {
			const findings = await store.listFindings();
			const evidence = await store.listEvidence();

			const content =
				input.format === "markdown" ? exportMarkdown(findings, evidence) : exportJson(findings, evidence);

			const outputPath = resolveOutputPath(defaultOutputDir, input.outputPath, input.format);
			if (!outputPath) {
				return {
					success: false,
					error: `outputPath must stay within ${resolve(defaultOutputDir)}`,
				};
			}

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
