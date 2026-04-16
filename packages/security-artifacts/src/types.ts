export type Severity = "info" | "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type FindingStatus = "candidate" | "validated" | "reported" | "fixed" | "closed";
export type EvidenceType = "http" | "file" | "terminal" | "browser" | "image" | "note" | "diff";

export interface CodeLocation {
	file: string;
	startLine: number;
	endLine: number;
	snippet?: string;
	label?: string;
	fixBefore?: string;
	fixAfter?: string;
}

export interface CvssBreakdown {
	attackVector: "N" | "A" | "L" | "P";
	attackComplexity: "L" | "H";
	privilegesRequired: "N" | "L" | "H";
	userInteraction: "N" | "R";
	scope: "U" | "C";
	confidentiality: "N" | "L" | "H";
	integrity: "N" | "L" | "H";
	availability: "N" | "L" | "H";
}

export interface Finding {
	id: string;
	title: string;
	category: string;
	severity: Severity;
	confidence: Confidence;
	status: FindingStatus;
	targets: string[];
	evidenceIds: string[];
	cwe?: string;
	cve?: string;
	cvssScore?: number;
	cvssVector?: string;
	cvssBreakdown?: CvssBreakdown;
	summary: string;
	technicalAnalysis: string;
	impact: string;
	remediation: string;
	endpoint?: string;
	method?: string;
	codeLocations?: CodeLocation[];
	createdAt: number;
	updatedAt: number;
}

export interface Evidence {
	id: string;
	findingId?: string;
	type: EvidenceType;
	title: string;
	content: unknown;
	targets: string[];
	createdAt: number;
}

export interface Note {
	id: string;
	title: string;
	content: string;
	category: "general" | "findings" | "methodology" | "questions" | "plan" | "wiki";
	tags: string[];
	createdAt: number;
	updatedAt: number;
}

export interface TargetMap {
	id: string;
	targets: string[];
	endpoints: string[];
	technologies: string[];
	notes: string;
	createdAt: number;
	updatedAt: number;
}

export interface RunSummary {
	runId: string;
	startedAt: number;
	completedAt?: number;
	findingCount: number;
	evidenceCount: number;
	targets: string[];
}
