import { type Static, Type } from "@sinclair/typebox";
import type { SecurityScope } from "../scope.js";
import { validateNetworkTargetInScope } from "../scope-policy.js";
import { quoteShellArg } from "../shell.js";
import type { ExecFn, SecurityTool, WorkspaceHandle } from "../types.js";

export interface HttpxResult {
	url: string;
	statusCode: number;
	title?: string;
	technologies?: string[];
	contentLength?: number;
	responseTime?: string;
}

export function parseHttpxOutput(raw: string): HttpxResult[] {
	const results: HttpxResult[] = [];
	for (const line of raw.split("\n")) {
		const trimmed = line.trim();
		if (!trimmed) continue;
		try {
			const obj = JSON.parse(trimmed) as Record<string, unknown>;
			results.push({
				url: String(obj.url ?? ""),
				statusCode: typeof obj.status_code === "number" ? obj.status_code : 0,
				title: typeof obj.title === "string" && obj.title ? obj.title : undefined,
				technologies: Array.isArray(obj.tech) ? (obj.tech as string[]) : undefined,
				contentLength: typeof obj.content_length === "number" ? obj.content_length : undefined,
				responseTime: typeof obj.response_time === "string" ? obj.response_time : undefined,
			});
		} catch {
			// skip malformed line
		}
	}
	return results;
}

const httpxSchema = Type.Object({
	target: Type.String({ description: "URL or host to probe with httpx" }),
	timeoutSeconds: Type.Optional(Type.Number({ description: "Per-request timeout in seconds. Default: 10" })),
});

type HttpxInput = Static<typeof httpxSchema>;

export function httpxTool(
	exec: ExecFn | null,
	workspace: WorkspaceHandle | undefined,
	scope?: SecurityScope,
): SecurityTool<HttpxInput> {
	return {
		name: "httpx_probe",
		label: "Httpx Probe",
		description:
			"Probe a target URL or host with httpx to collect status codes, page titles, and technology fingerprints. " +
			"Returns structured NDJSON results. " +
			"Requires the sandbox container to have httpx installed.",
		parameters: httpxSchema,
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
			const timeout = input.timeoutSeconds ?? 10;
			const command =
				`httpx -u ${quoteShellArg(input.target)} ` +
				`-json -status-code -title -tech-detect -content-length -response-time -silent -timeout ${quoteShellArg(String(timeout))}`;
			const result = await exec(workspace.workspaceId, command, { timeoutMs: (timeout + 30) * 1000 });
			const httpxResults = parseHttpxOutput(result.stdout);
			return {
				success: true,
				results: httpxResults,
				resultCount: httpxResults.length,
			};
		},
	};
}
