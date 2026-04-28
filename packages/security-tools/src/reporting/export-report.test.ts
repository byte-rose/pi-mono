import assert from "node:assert/strict";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, it } from "node:test";
import { ArtifactStore } from "@byte-rose/nyati-security-artifacts";
import { exportReportTool } from "./export-report.js";

const tempDirs: string[] = [];

async function createTempDir(): Promise<string> {
	const dir = await mkdtemp(join(tmpdir(), "nyati-export-report-"));
	tempDirs.push(dir);
	return dir;
}

describe("exportReportTool", () => {
	afterEach(async () => {
		await Promise.all(tempDirs.splice(0).map((dir) => rm(dir, { recursive: true, force: true })));
	});

	it("writes reports inside the configured output directory", async () => {
		const runDir = await createTempDir();
		const outputDir = join(runDir, "reports");
		const store = new ArtifactStore(runDir);
		const tool = exportReportTool(store, outputDir);

		const result = await tool.execute({ format: "markdown", outputPath: "nested/report.md" });
		assert.strictEqual(result.success, true);
		assert.ok(String(result.outputPath).startsWith(outputDir));
		const content = await readFile(String(result.outputPath), "utf-8");
		assert.match(content, /Security Assessment Report/);
	});

	it("rejects paths that escape the configured output directory", async () => {
		const runDir = await createTempDir();
		const outputDir = join(runDir, "reports");
		const store = new ArtifactStore(runDir);
		const tool = exportReportTool(store, outputDir);

		const result = await tool.execute({ format: "json", outputPath: "../escape.json" });
		assert.strictEqual(result.success, false);
		assert.match(String(result.error), /must stay within/);
	});
});
