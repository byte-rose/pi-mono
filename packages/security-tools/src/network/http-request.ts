// packages/security-tools/src/network/http-request.ts

import { BlockList, isIP } from "node:net";
import { type Static, Type } from "@sinclair/typebox";
import type { SecurityScope } from "../scope.js";
import { isDomainAllowed } from "../scope-policy.js";
import type { SecurityTool } from "../types.js";

const MAX_REDIRECTS = 5;

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
type IpAddressType = "ipv4" | "ipv6";

function getIpAddressType(hostname: string): IpAddressType | null {
	const family = isIP(hostname);
	if (family === 4) return "ipv4";
	if (family === 6) return "ipv6";
	return null;
}

function parseCidr(cidr: string): { address: string; prefix: number; type: IpAddressType } | null {
	const [address, prefixText, ...rest] = cidr.trim().split("/");
	if (!address || !prefixText || rest.length > 0) return null;

	const type = getIpAddressType(address);
	if (!type) return null;

	const prefix = Number(prefixText);
	const maxPrefix = type === "ipv4" ? 32 : 128;
	if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) return null;

	return { address, prefix, type };
}

function buildBlockList(cidrs: string[]): { blockList: BlockList } | { error: string } {
	const blockList = new BlockList();
	for (const cidr of cidrs) {
		const parsed = parseCidr(cidr);
		if (!parsed) {
			return { error: `Invalid CIDR in scope: ${cidr}` };
		}
		blockList.addSubnet(parsed.address, parsed.prefix, parsed.type);
	}
	return { blockList };
}

function validateHostnameInScope(scope: SecurityScope, hostname: string): string | null {
	if (!hostname.trim()) {
		return "Host is outside scope.";
	}

	const ipAddressType = getIpAddressType(hostname);
	if (ipAddressType) {
		const deniedBlockList = buildBlockList(scope.network.deniedCidrs);
		if ("error" in deniedBlockList) {
			return deniedBlockList.error;
		}
		if (deniedBlockList.blockList.check(hostname, ipAddressType)) {
			return `IP '${hostname}' is outside scope. Check allowedCidrs / deniedCidrs.`;
		}

		if (scope.network.allowedCidrs.length === 0) {
			return null;
		}

		const allowedBlockList = buildBlockList(scope.network.allowedCidrs);
		if ("error" in allowedBlockList) {
			return allowedBlockList.error;
		}
		if (!allowedBlockList.blockList.check(hostname, ipAddressType)) {
			return `IP '${hostname}' is outside scope. Check allowedCidrs / deniedCidrs.`;
		}
		return null;
	}

	if (!isDomainAllowed(scope, hostname)) {
		return `Domain '${hostname}' is outside scope. Check allowedDomains / deniedDomains.`;
	}

	return null;
}

function getResponseHeaders(response: Response): Record<string, string> {
	const responseHeaders: Record<string, string> = {};
	response.headers.forEach((value, key) => {
		responseHeaders[key] = value;
	});
	return responseHeaders;
}

function isRedirectStatus(statusCode: number): boolean {
	return statusCode >= 300 && statusCode < 400;
}

function resolveScopedUrl(scope: SecurityScope, url: string, baseUrl?: string): { url: URL } | { error: string } {
	let parsedUrl: URL;
	try {
		parsedUrl = baseUrl ? new URL(url, baseUrl) : new URL(url);
	} catch {
		return { error: `Invalid URL: ${url}` };
	}

	const scopeError = validateHostnameInScope(scope, parsedUrl.hostname);
	if (scopeError) {
		return { error: scopeError };
	}

	return { url: parsedUrl };
}

export function httpRequestTool(scope: SecurityScope): SecurityTool<HttpRequestInput> {
	return {
		name: "http_request",
		label: "HTTP Request",
		description:
			"Make a raw HTTP request to a target URL for direct API verification, replay, or header inspection. " +
			"Each request and redirect hop must remain within scope. " +
			"Returns status code, headers, and raw response body.",
		parameters: httpRequestSchema,
		async execute(input) {
			const initialUrl = resolveScopedUrl(scope, input.url);
			if ("error" in initialUrl) {
				return { success: false, error: initialUrl.error };
			}

			const controller = new AbortController();
			const timeoutId = setTimeout(() => controller.abort(), input.timeoutMs ?? 10_000);
			const shouldFollowRedirects = input.followRedirects !== false;

			try {
				let currentUrl = initialUrl.url;
				let redirectCount = 0;

				while (true) {
					const response = await fetch(currentUrl, {
						method: input.method ?? "GET",
						headers: input.headers,
						body: input.body,
						redirect: "manual",
						signal: controller.signal,
					});

					if (!shouldFollowRedirects || !isRedirectStatus(response.status)) {
						return {
							success: true,
							statusCode: response.status,
							headers: getResponseHeaders(response),
							body: await response.text(),
							finalUrl: currentUrl.toString(),
							redirectCount,
						};
					}

					const location = response.headers.get("location");
					if (!location) {
						return {
							success: true,
							statusCode: response.status,
							headers: getResponseHeaders(response),
							body: await response.text(),
							finalUrl: currentUrl.toString(),
							redirectCount,
						};
					}

					if (redirectCount >= MAX_REDIRECTS) {
						return {
							success: false,
							error: `Too many redirects. Maximum allowed redirects is ${MAX_REDIRECTS}.`,
						};
					}

					const nextUrl = resolveScopedUrl(scope, location, currentUrl.toString());
					if ("error" in nextUrl) {
						return {
							success: false,
							error: `Redirect blocked: ${nextUrl.error}`,
						};
					}

					currentUrl = nextUrl.url;
					redirectCount += 1;
				}
			} catch (err) {
				const message = err instanceof Error ? err.message : String(err);
				return { success: false, error: message };
			} finally {
				clearTimeout(timeoutId);
			}
		},
	};
}
