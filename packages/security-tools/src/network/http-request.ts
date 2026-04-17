// packages/security-tools/src/network/http-request.ts

import type { SecurityScope } from "@byte-rose/nyati-security-agent";
import { type Static, Type } from "@sinclair/typebox";
import type { SecurityTool } from "../types.js";

const httpRequestSchema = Type.Object({
	url: Type.String({ description: "Fully-qualified URL to request" }),
	method: Type.Optional(
		Type.Union([
			Type.Literal("GET"),
			Type.Literal("POST"),
			Type.Literal("PUT"),
			Type.Literal("DELETE"),
			Type.Literal("PATCH"),
			Type.Literal("HEAD"),
			Type.Literal("OPTIONS"),
		]),
	),
	headers: Type.Optional(Type.Record(Type.String(), Type.String())),
	body: Type.Optional(Type.String({ description: "Request body (string)" })),
	followRedirects: Type.Optional(Type.Boolean()),
	timeoutMs: Type.Optional(Type.Number({ description: "Timeout in milliseconds. Default: 10000" })),
});

type HttpRequestInput = Static<typeof httpRequestSchema>;

function isDomainAllowed(scope: SecurityScope, hostname: string): boolean {
	if (!hostname.trim()) return false;
	if (scope.network.deniedDomains.some((d) => hostname === d || hostname.endsWith(`.${d}`))) return false;
	if (scope.network.allowedDomains.length === 0) return true;
	return scope.network.allowedDomains.some((d) => hostname === d || hostname.endsWith(`.${d}`));
}

export function httpRequestTool(scope: SecurityScope): SecurityTool<HttpRequestInput> {
	return {
		name: "http_request",
		label: "HTTP Request",
		description:
			"Make an HTTP request to a target URL. " +
			"Domain must be within scope (allowedDomains, not in deniedDomains). " +
			"Returns status code, headers, and response body.",
		parameters: httpRequestSchema,
		async execute(input) {
			let hostname: string;
			try {
				hostname = new URL(input.url).hostname;
			} catch {
				return { success: false, error: `Invalid URL: ${input.url}` };
			}

			if (!isDomainAllowed(scope, hostname)) {
				return {
					success: false,
					error: `Domain '${hostname}' is outside scope. Check allowedDomains / deniedDomains.`,
				};
			}

			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), input.timeoutMs ?? 10_000);

			try {
				const response = await fetch(input.url, {
					method: input.method ?? "GET",
					headers: input.headers,
					body: input.body,
					redirect: input.followRedirects === false ? "manual" : "follow",
					signal: controller.signal,
				});

				const responseHeaders: Record<string, string> = {};
				response.headers.forEach((value, key) => {
					responseHeaders[key] = value;
				});
				const body = await response.text();

				return {
					success: true,
					statusCode: response.status,
					headers: responseHeaders,
					body,
				};
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				return { success: false, error: message };
			} finally {
				clearTimeout(timeoutId);
			}
		},
	};
}
