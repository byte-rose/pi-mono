// packages/security-tools/src/runtime/add-scope-target.ts

import { type Static, Type } from "@sinclair/typebox";
import type { SecurityScope, SecurityTarget, WebApplicationTarget } from "../scope.js";
import { isDomainAllowed, normalizeHostname } from "../scope-policy.js";
import type { SecurityTool } from "../types.js";

const addScopeTargetSchema = Type.Object({
	url: Type.String({
		description: "Fully-qualified HTTP(S) URL for the web application target to add to the active scope.",
	}),
	id: Type.Optional(Type.String({ description: "Optional target id. Generated when omitted." })),
	origins: Type.Optional(
		Type.Array(Type.String(), {
			description: "Optional allowed origins for this web application. Defaults to the URL origin.",
		}),
	),
	discoveredFrom: Type.Optional(
		Type.String({ description: "URL, target id, or note describing where this target came from." }),
	),
	reason: Type.Optional(Type.String({ description: "Why this target is considered in-engagement scope." })),
	confidence: Type.Optional(Type.Union([Type.Literal("low"), Type.Literal("medium"), Type.Literal("high")])),
});

type AddScopeTargetInput = Static<typeof addScopeTargetSchema>;

export interface ScopeMutationEvent {
	type: "target_added";
	timestamp: number;
	target: WebApplicationTarget;
	targetCount: number;
	allowedDomains: string[];
	discoveredFrom?: string;
	reason?: string;
}

export interface AddScopeTargetOptions {
	addedBy?: "user" | "agent" | "system";
	onScopeChanged?: (event: ScopeMutationEvent) => Promise<void> | void;
}

function includesDomain(domains: string[], hostname: string): boolean {
	const normalized = normalizeHostname(hostname);
	return domains.some((domain) => normalizeHostname(domain).replace(/^\*\./, "") === normalized);
}

function nextTargetId(targets: SecurityTarget[]): string {
	const used = new Set(targets.map((target) => target.id));
	let index = targets.length + 1;
	let id = `t${index}`;

	while (used.has(id)) {
		index += 1;
		id = `t${index}`;
	}

	return id;
}

function normalizeWebTargetValue(value: string): string {
	try {
		return new URL(value).toString();
	} catch {
		return value;
	}
}

function isExistingWebTarget(target: SecurityTarget, value: string): target is WebApplicationTarget {
	return target.type === "web_application" && normalizeWebTargetValue(target.value) === value;
}

function hasTarget(scope: SecurityScope, value: string): boolean {
	return scope.targets.some((target) => isExistingWebTarget(target, value));
}

function parseWebTarget(input: AddScopeTargetInput): { target: WebApplicationTarget; hostname: string } | string {
	let url: URL;
	try {
		url = new URL(input.url);
	} catch {
		return `Invalid target URL: ${input.url}`;
	}

	if (url.protocol !== "http:" && url.protocol !== "https:") {
		return `Unsupported target URL protocol: ${url.protocol}`;
	}

	const hostname = normalizeHostname(url.hostname);
	if (!hostname) {
		return `Invalid target URL hostname: ${input.url}`;
	}

	const origins = input.origins && input.origins.length > 0 ? input.origins : [url.origin];

	return {
		hostname,
		target: {
			id: input.id?.trim() || "",
			type: "web_application",
			value: url.toString(),
			origins,
		},
	};
}

export function addScopeTargetTool(
	scope: SecurityScope,
	options: AddScopeTargetOptions = {},
): SecurityTool<AddScopeTargetInput> {
	return {
		name: "add_scope_target",
		label: "Add Scope Target",
		description:
			"Expand the active security scope during a run by adding a new web application target. " +
			"Use this before browser_action or other scoped network workflows on a discovered in-engagement URL.",
		parameters: addScopeTargetSchema,
		async execute(input) {
			const parsed = parseWebTarget(input);
			if (typeof parsed === "string") {
				return { success: false, error: parsed };
			}

			if (!isDomainAllowed({ ...scope, network: { ...scope.network, allowedDomains: [] } }, parsed.hostname)) {
				return {
					success: false,
					error: `Domain '${parsed.hostname}' is denied by the current scope and cannot be added.`,
				};
			}

			if (input.id && scope.targets.some((target) => target.id === input.id)) {
				return { success: false, error: `Target id '${input.id}' already exists in scope.` };
			}

			if (hasTarget(scope, parsed.target.value)) {
				return {
					success: true,
					added: false,
					target: scope.targets.find((target) => isExistingWebTarget(target, parsed.target.value)),
					targets: scope.targets,
					allowedDomains: scope.network.allowedDomains,
				};
			}

			const target = {
				...parsed.target,
				id: parsed.target.id || nextTargetId(scope.targets),
				status: "active" as const,
				provenance: {
					addedAt: Date.now(),
					addedBy: options.addedBy ?? "agent",
					discoveredFrom: input.discoveredFrom,
					reason: input.reason,
					confidence: input.confidence ?? "medium",
				},
			};

			scope.targets.push(target);
			if (
				scope.network.allowedDomains.length > 0 &&
				!includesDomain(scope.network.allowedDomains, parsed.hostname)
			) {
				scope.network.allowedDomains.push(parsed.hostname);
			}
			scope.metadata.verified = false;
			scope.metadata.updatedAt = Date.now();

			const event: ScopeMutationEvent = {
				type: "target_added",
				timestamp: scope.metadata.updatedAt,
				target,
				targetCount: scope.targets.length,
				allowedDomains: scope.network.allowedDomains,
				discoveredFrom: input.discoveredFrom,
				reason: input.reason,
			};
			let auditError: string | undefined;
			try {
				await options.onScopeChanged?.(event);
			} catch (error) {
				auditError = error instanceof Error ? error.message : String(error);
			}

			return {
				success: true,
				added: true,
				target,
				targets: scope.targets,
				allowedDomains: scope.network.allowedDomains,
				auditError,
			};
		},
	};
}
