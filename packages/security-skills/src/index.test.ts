import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { defaultSkillsDir, formatSkillsSection, loadSkillsForScope, relevantSkillPaths } from "./index.js";

const baseCtx = {
	scanMode: "quick" as const,
	executionMode: "read_only" as const,
	targetTypes: ["web_application" as const],
};

describe("relevantSkillPaths", () => {
	it("always includes scan_modes/<scanMode>", () => {
		const paths = relevantSkillPaths({ ...baseCtx, scanMode: "standard" });
		assert.ok(paths.includes("scan_modes/standard"));
	});

	it("includes web vuln skills for web_application target", () => {
		const paths = relevantSkillPaths(baseCtx);
		assert.ok(paths.includes("vulnerabilities/xss"));
		assert.ok(paths.includes("vulnerabilities/sqli"));
		assert.ok(paths.includes("vulnerabilities/idor"));
		assert.ok(paths.includes("vulnerabilities/ssrf"));
	});

	it("includes web vuln skills for api_collection target", () => {
		const paths = relevantSkillPaths({ ...baseCtx, targetTypes: ["api_collection"] });
		assert.ok(paths.includes("vulnerabilities/xss"));
	});

	it("includes rce only for exploit executionMode", () => {
		const pathsSafe = relevantSkillPaths(baseCtx);
		assert.ok(!pathsSafe.includes("vulnerabilities/rce"));
		const pathsExploit = relevantSkillPaths({ ...baseCtx, executionMode: "exploit" });
		assert.ok(pathsExploit.includes("vulnerabilities/rce"));
	});

	it("always includes tooling skills", () => {
		const paths = relevantSkillPaths(baseCtx);
		assert.ok(paths.includes("tooling/nuclei"));
		assert.ok(paths.includes("tooling/semgrep"));
		assert.ok(paths.includes("tooling/httpx"));
	});

	it("excludes web vuln skills for non-web targets", () => {
		const paths = relevantSkillPaths({ ...baseCtx, targetTypes: ["ip_address"] });
		assert.ok(!paths.includes("vulnerabilities/xss"));
	});
});

describe("loadSkillsForScope", () => {
	it("loads real skill files from defaultSkillsDir", () => {
		const skills = loadSkillsForScope(baseCtx, defaultSkillsDir);
		assert.ok(skills.length > 0, "expected at least one skill to load");
	});

	it("loaded skills have non-empty name and content", () => {
		const skills = loadSkillsForScope(baseCtx, defaultSkillsDir);
		for (const skill of skills) {
			assert.ok(skill.name.length > 0, `empty name for skill at ${skill.path}`);
			assert.ok(skill.content.length > 0, `empty content for skill at ${skill.path}`);
		}
	});

	it("strips YAML frontmatter from skill content", () => {
		const skills = loadSkillsForScope(baseCtx, defaultSkillsDir);
		for (const skill of skills) {
			assert.ok(!skill.content.startsWith("---"), `frontmatter not stripped in ${skill.name}`);
		}
	});

	it("returns empty array when skillsDir does not exist", () => {
		const skills = loadSkillsForScope(baseCtx, "/nonexistent/path/to/skills");
		assert.deepStrictEqual(skills, []);
	});
});

describe("formatSkillsSection", () => {
	it("returns empty string for empty skills array", () => {
		assert.strictEqual(formatSkillsSection([]), "");
	});

	it("returns section header with skill names and content", () => {
		const skills = [
			{ name: "xss", path: "/fake/xss/SKILL.md", content: "XSS content here." },
			{ name: "nuclei", path: "/fake/nuclei/SKILL.md", content: "Nuclei content here." },
		];
		const section = formatSkillsSection(skills);
		assert.ok(section.includes("# Skills"));
		assert.ok(section.includes("## xss"));
		assert.ok(section.includes("XSS content here."));
		assert.ok(section.includes("## nuclei"));
	});
});
