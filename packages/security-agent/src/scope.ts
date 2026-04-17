// packages/security-agent/src/scope.ts
// Scope types live in security-tools to avoid a circular dependency.
export type {
	AllowedAction,
	ApiCollectionTarget,
	AssessmentMode,
	ExecutionMode,
	FilesystemPolicy,
	IpAddressTarget,
	LocalCodeTarget,
	NetworkPolicy,
	ReportingPolicy,
	RepositoryTarget,
	ScanMode,
	ScopeExclusion,
	SecurityScope,
	SecurityTarget,
	WebApplicationTarget,
} from "@byte-rose/nyati-security-tools";
