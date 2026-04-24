import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));

/** Absolute path to the `skills/` directory bundled with this package. */
export const defaultSkillsDir = join(__dirname, "..", "skills");

export interface SkillSelectionContext {
	scanMode: "quick" | "standard" | "deep";
	executionMode: "read_only" | "validate" | "exploit" | "remediate";
	targetTypes: Array<"web_application" | "api_collection" | "repository" | "local_code" | "ip_address">;
}

export interface LoadedSkill {
	name: string;
	path: string;
	content: string;
}

/** Return the relative skill directory paths relevant for the given context. */
export function relevantSkillPaths(ctx: SkillSelectionContext): string[] {
	const paths: string[] = [];

	// Scan mode
	paths.push(`scan_modes/${ctx.scanMode}`);

	// Vulnerability skills for web/api targets
	const isWebTarget = ctx.targetTypes.some((t) => t === "web_application" || t === "api_collection");
	if (isWebTarget) {
		paths.push("tooling/agent-browser");
		paths.push("vulnerabilities/xss", "vulnerabilities/sqli", "vulnerabilities/idor", "vulnerabilities/ssrf");
		if (ctx.executionMode === "exploit" || ctx.executionMode === "validate") {
			paths.push("vulnerabilities/rce");
		}
	}

	// Tooling skills
	paths.push("tooling/nuclei", "tooling/semgrep", "tooling/httpx");

	return paths;
}

/** Load skill files from `skillsDir` for the given context. Skips missing files silently. */
export function loadSkillsForScope(ctx: SkillSelectionContext, skillsDir: string): LoadedSkill[] {
	const skills: LoadedSkill[] = [];
	for (const relPath of relevantSkillPaths(ctx)) {
		const skillFile = join(skillsDir, relPath, "SKILL.md");
		if (!existsSync(skillFile)) continue;
		try {
			const raw = readFileSync(skillFile, "utf-8");
			const content = raw.replace(/^---[\s\S]*?---\n/, "").trim();
			skills.push({ name: relPath.split("/").pop() ?? relPath, path: skillFile, content });
		} catch {
			// skip unreadable file
		}
	}
	return skills;
}

/** Format loaded skills into a `# Skills` section for injection into a system prompt. */
export function formatSkillsSection(skills: LoadedSkill[]): string {
	if (skills.length === 0) return "";
	const body = skills.map((s) => `## ${s.name}\n\n${s.content}`).join("\n\n---\n\n");
	return `\n\n# Skills\n\n${body}`;
}
