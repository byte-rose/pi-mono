import { homedir } from "node:os";
import { join } from "node:path";
import type { SecurityScope } from "./scope.js";

function runBase(engagementId: string): string {
	return join(homedir(), ".nyati", "runs", engagementId);
}

export function quickBlackboxWebScan(target: string, engagementId: string): SecurityScope {
	const url = new URL(target);
	const base = runBase(engagementId);
	return {
		engagementId,
		mode: "blackbox",
		scanMode: "quick",
		executionMode: "read_only",
		targets: [{ id: "t1", type: "web_application", value: target, origins: [url.origin] }],
		exclusions: [],
		allowedActions: ["run_commands", "browser_test", "create_reports"],
		filesystem: { readableRoots: [], writableRoots: [], blockedPaths: [], artifactDir: join(base, "artifacts") },
		network: {
			allowedDomains: [url.hostname],
			deniedDomains: [],
			allowedCidrs: [],
			deniedCidrs: [],
			browserEnabled: true,
			proxyEnabled: false,
		},
		reporting: { outputDir: join(base, "reports"), formats: ["markdown"] },
		metadata: { source: "cli", verified: false, createdAt: Date.now(), updatedAt: Date.now() },
	};
}

export function standardBlackboxWebScan(target: string, engagementId: string): SecurityScope {
	const url = new URL(target);
	const base = runBase(engagementId);
	return {
		engagementId,
		mode: "blackbox",
		scanMode: "standard",
		executionMode: "validate",
		targets: [{ id: "t1", type: "web_application", value: target, origins: [url.origin] }],
		exclusions: [],
		allowedActions: ["run_commands", "network_scan", "browser_test", "create_reports"],
		filesystem: { readableRoots: [], writableRoots: [], blockedPaths: [], artifactDir: join(base, "artifacts") },
		network: {
			allowedDomains: [url.hostname],
			deniedDomains: [],
			allowedCidrs: [],
			deniedCidrs: [],
			browserEnabled: true,
			proxyEnabled: false,
		},
		reporting: { outputDir: join(base, "reports"), formats: ["markdown", "json"] },
		metadata: { source: "cli", verified: false, createdAt: Date.now(), updatedAt: Date.now() },
	};
}

export function deepWhiteboxAudit(target: string, engagementId: string, workspacePath: string): SecurityScope {
	const url = new URL(target);
	const base = runBase(engagementId);
	return {
		engagementId,
		mode: "whitebox",
		scanMode: "deep",
		executionMode: "exploit",
		targets: [
			{ id: "t1", type: "web_application", value: target, origins: [url.origin] },
			{ id: "t2", type: "local_code", value: workspacePath, workspacePath },
		],
		exclusions: [],
		allowedActions: ["read_files", "write_files", "run_commands", "network_scan", "browser_test", "create_reports"],
		filesystem: {
			readableRoots: [workspacePath],
			writableRoots: [],
			blockedPaths: [],
			artifactDir: join(base, "artifacts"),
		},
		network: {
			allowedDomains: [url.hostname],
			deniedDomains: [],
			allowedCidrs: [],
			deniedCidrs: [],
			browserEnabled: true,
			proxyEnabled: false,
		},
		reporting: { outputDir: join(base, "reports"), formats: ["markdown", "json", "sarif"] },
		metadata: { source: "cli", verified: false, createdAt: Date.now(), updatedAt: Date.now() },
	};
}
