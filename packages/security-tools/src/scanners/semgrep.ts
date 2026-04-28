import { type Static, Type } from "@sinclair/typebox";
import { quoteShellArg } from "../shell.js";
import type { ExecFn, SecurityTool, WorkspaceHandle } from "../types.js";

export interface SemgrepFinding {
	ruleId: string;
	path: string;
	line: number;
	message: string;
	severity: string;
	cwe?: string[];
}

export function parseSemgrepOutput(raw: string): { findings: SemgrepFinding[]; errors: string[] } {
	let parsed: Record<string, unknown>;
	try {
		parsed = JSON.parse(raw) as Record<string, unknown>;
	} catch (err) {
		const message = err instanceof Error ? err.message : String(err);
		return { findings: [], errors: [`JSON parse error: ${message}`] };
	}

	const rawResults = Array.isArray(parsed.results) ? (parsed.results as Record<string, unknown>[]) : [];
	const rawErrors = Array.isArray(parsed.errors) ? (parsed.errors as Record<string, unknown>[]) : [];

	const findings: SemgrepFinding[] = rawResults.map((r) => {
		const extra = (r.extra ?? {}) as Record<string, unknown>;
		const metadata = (extra.metadata ?? {}) as Record<string, unknown>;
		const cweRaw = metadata.cwe;
		const cwe = Array.isArray(cweRaw) ? (cweRaw as string[]) : undefined;
		const start = (r.start ?? {}) as Record<string, unknown>;
		return {
			ruleId: String(r.check_id ?? ""),
			path: String(r.path ?? ""),
			line: typeof start.line === "number" ? start.line : 0,
			message: String(extra.message ?? ""),
			severity: String(extra.severity ?? ""),
			cwe,
		};
	});

	const errors: string[] = rawErrors.map((e) => {
		const type = e.type ? `${e.type}: ` : "";
		return `${type}${String(e.message ?? e)}`;
	});

	return { findings, errors };
}

const semgrepSchema = Type.Object({
	config: Type.String({ description: "Semgrep config: 'auto', 'p/owasp-top-ten', or path to rules file" }),
	path: Type.String({ description: "Path inside container to scan. Default: /workspace" }),
	timeoutSeconds: Type.Optional(Type.Number({ description: "Scan timeout in seconds. Default: 120" })),
});

type SemgrepInput = Static<typeof semgrepSchema>;

export function semgrepTool(exec: ExecFn | null, workspace: WorkspaceHandle | undefined): SecurityTool<SemgrepInput> {
	return {
		name: "semgrep_scan",
		label: "Semgrep Scan",
		description:
			"Run semgrep static analysis on code inside the sandbox container. " +
			"Returns structured findings and parse errors. " +
			"Requires the sandbox container to have semgrep installed.",
		parameters: semgrepSchema,
		async execute(input) {
			if (!exec || !workspace) {
				return { success: false, error: "No sandbox available. Start session with useSandbox: true." };
			}
			const timeout = input.timeoutSeconds ?? 120;
			const command = `semgrep --config ${quoteShellArg(input.config)} ${quoteShellArg(input.path)} --json --quiet`;
			const result = await exec(workspace.workspaceId, command, { timeoutMs: (timeout + 10) * 1000 });
			const { findings, errors } = parseSemgrepOutput(result.stdout);
			return {
				success: true,
				findings,
				findingCount: findings.length,
				errors: errors.length > 0 ? errors : undefined,
			};
		},
	};
}
