// packages/security-tools/src/scope.ts

export type AssessmentMode = "blackbox" | "whitebox" | "hybrid";
export type ScanMode = "quick" | "standard" | "deep";
export type ExecutionMode = "read_only" | "validate" | "exploit" | "remediate";
export type AllowedAction =
	| "read_files"
	| "write_files"
	| "run_commands"
	| "network_scan"
	| "http_test"
	| "browser_test"
	| "modify_code"
	| "create_reports";

export type SecurityTarget =
	| RepositoryTarget
	| LocalCodeTarget
	| WebApplicationTarget
	| IpAddressTarget
	| ApiCollectionTarget;

export interface RepositoryTarget {
	id: string;
	type: "repository";
	value: string;
	workspacePath?: string;
	defaultBranch?: string;
}

export interface LocalCodeTarget {
	id: string;
	type: "local_code";
	value: string;
	workspacePath: string;
}

export interface WebApplicationTarget {
	id: string;
	type: "web_application";
	value: string;
	origins: string[];
	authProfileId?: string;
}

export interface IpAddressTarget {
	id: string;
	type: "ip_address";
	value: string;
	ports?: number[];
}

export interface ApiCollectionTarget {
	id: string;
	type: "api_collection";
	value: string;
	workspacePath?: string;
}

export interface ScopeExclusion {
	pattern: string;
	reason?: string;
}

export interface FilesystemPolicy {
	readableRoots: string[];
	writableRoots: string[];
	blockedPaths: string[];
	artifactDir: string;
}

export interface NetworkPolicy {
	allowedDomains: string[];
	deniedDomains: string[];
	allowedCidrs: string[];
	deniedCidrs: string[];
	browserEnabled: boolean;
	proxyEnabled: boolean;
}

export interface ReportingPolicy {
	outputDir: string;
	formats: Array<"markdown" | "json" | "sarif" | "html">;
}

export interface SecurityScope {
	engagementId: string;
	mode: AssessmentMode;
	scanMode: ScanMode;
	executionMode: ExecutionMode;
	targets: SecurityTarget[];
	exclusions: ScopeExclusion[];
	allowedActions: AllowedAction[];
	filesystem: FilesystemPolicy;
	network: NetworkPolicy;
	reporting: ReportingPolicy;
	metadata: {
		source: "cli" | "config" | "session" | "api";
		verified: boolean;
		createdAt: number;
		updatedAt: number;
	};
}
