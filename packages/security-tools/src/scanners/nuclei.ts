import { type Static, Type } from "@sinclair/typebox";
import type { SecurityScope } from "../scope.js";
import { validateNetworkTargetInScope } from "../scope-policy.js";
import { quoteShellArg } from "../shell.js";
import type { ExecFn, SecurityTool, WorkspaceHandle } from "../types.js";

export interface NucleiFinding {
	templateId: string;
	name: string;
	severity: string;
	host: string;
	matched: string;
	description?: string;
	reference?: string[];
	tags?: string[];
}

export function parseNucleiOutput(raw: string): NucleiFinding[] {
	const findings: NucleiFinding[] = [];
	for (const line of raw.split("\n")) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		try {
			const obj = JSON.parse(trimmed) as Record<string, unknown>;
			const info = (obj.info ?? {}) as Record<string, unknown>;
			findings.push({
				templateId: String(obj["template-id"] ?? ""),
				name: String(info.name ?? ""),
				severity: String(info.severity ?? "info"),
				host: String(obj.host ?? ""),
				matched: String(obj.matched ?? obj["matched-at"] ?? ""),
				description: typeof obj.description === "string" ? obj.description : undefined,
				reference: Array.isArray(info.reference) ? (info.reference as string[]) : undefined,
				tags: Array.isArray(info.tags) ? (info.tags as string[]) : undefined,
			});
		} catch {
			// skip malformed line
		}
	}
	return findings;
}

const nucleiSchema = Type.Object({
	target: Type.String({ description: "URL or host to scan with nuclei" }),
	template: Type.Optional(Type.String({ description: "Nuclei template path or tag. Default: all" })),
	timeoutSeconds: Type.Optional(Type.Number({ description: "Scan timeout in seconds. Default: 120" })),
});

type NucleiInput = Static<typeof nucleiSchema>;

export function nucleiTool(
	exec: ExecFn | null,
	workspace: WorkspaceHandle | undefined,
	scope?: SecurityScope,
): SecurityTool<NucleiInput> {
	return {
		name: "nuclei_scan",
		label: "Nuclei Scan",
		description:
			"Run the nuclei vulnerability scanner against a target. " +
			"Returns structured findings parsed from NDJSON output. " +
			"Requires the sandbox container to have nuclei installed.",
		parameters: nucleiSchema,
		async execute(input) {
			if (!exec || !workspace) {
				return { success: false, error: "No sandbox available. Start session with useSandbox: true." };
			}
			if (scope) {
				const scopeCheck = validateNetworkTargetInScope(scope, input.target);
				if (!scopeCheck.ok) {
					return { success: false, error: scopeCheck.error };
				}
			}
			const templateArg = input.template ? ` -t ${quoteShellArg(input.template)}` : "";
			const timeout = input.timeoutSeconds ?? 120;
			const command = `nuclei -u ${quoteShellArg(input.target)} -jsonl${templateArg} -timeout ${timeout} -silent`;
			const result = await exec(workspace.workspaceId, command, { timeoutMs: (timeout + 10) * 1000 });
			const findings = parseNucleiOutput(result.stdout);
			return {
				success: true,
				findings,
				findingCount: findings.length,
				stderr: result.stderr || undefined,
			};
		},
	};
}
