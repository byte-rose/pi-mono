import type { SecurityScope, SecurityTarget } from "./scope.js";

export interface ParsedNetworkTarget {
	hostname: string;
	url?: URL;
}

export function normalizeHostname(hostname: string): string {
	return hostname.trim().toLowerCase().replace(/\.$/, "");
}

function hostnameMatchesDomain(hostname: string, domain: string): boolean {
	const normalizedHostname = normalizeHostname(hostname);
	const normalizedDomain = normalizeHostname(domain).replace(/^\*\./, "");
	return normalizedHostname === normalizedDomain || normalizedHostname.endsWith(`.${normalizedDomain}`);
}

function ipv4ToNumber(value: string): number | undefined {
	const parts = value.split(".");
	if (parts.length !== 4) {
		return undefined;
	}

	let result = 0;
	for (const part of parts) {
		if (!/^\d+$/.test(part)) {
			return undefined;
		}
		const octet = Number(part);
		if (octet < 0 || octet > 255) {
			return undefined;
		}
		result = (result << 8) + octet;
	}

	return result >>> 0;
}

function cidrContainsIp(cidr: string, ip: string): boolean {
	const [range, prefixText] = cidr.split("/");
	const ipNumber = ipv4ToNumber(ip);
	const rangeNumber = range ? ipv4ToNumber(range) : undefined;
	const prefix = prefixText === undefined ? 32 : Number(prefixText);

	if (ipNumber === undefined || rangeNumber === undefined || !Number.isInteger(prefix) || prefix < 0 || prefix > 32) {
		return false;
	}

	const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
	return (ipNumber & mask) === (rangeNumber & mask);
}

function cidrsContainIp(cidrs: string[], hostname: string): boolean {
	return ipv4ToNumber(hostname) !== undefined && cidrs.some((cidr) => cidrContainsIp(cidr.trim(), hostname));
}

export function isDomainAllowed(scope: SecurityScope, hostname: string): boolean {
	const normalized = normalizeHostname(hostname);
	if (!normalized) {
		return false;
	}

	if (scope.network.deniedDomains.some((domain) => hostnameMatchesDomain(normalized, domain))) {
		return false;
	}
	if (cidrsContainIp(scope.network.deniedCidrs, normalized)) {
		return false;
	}
	if (scope.network.allowedDomains.length === 0 && scope.network.allowedCidrs.length === 0) {
		return true;
	}
	if (scope.network.allowedDomains.some((domain) => hostnameMatchesDomain(normalized, domain))) {
		return true;
	}
	if (cidrsContainIp(scope.network.allowedCidrs, normalized)) {
		return true;
	}

	return scope.network.allowedDomains.length === 0 && ipv4ToNumber(normalized) === undefined;
}

export function parseNetworkTarget(value: string): ParsedNetworkTarget | string {
	const trimmed = value.trim();
	if (!trimmed) {
		return "Target cannot be empty.";
	}
	if (/\s/.test(trimmed)) {
		return `Target contains whitespace: ${value}`;
	}

	const candidate = /^[A-Za-z][A-Za-z0-9+.-]*:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`;
	let url: URL;
	try {
		url = new URL(candidate);
	} catch {
		return `Invalid network target: ${value}`;
	}

	if (!url.hostname) {
		return `Invalid network target hostname: ${value}`;
	}

	return {
		hostname: normalizeHostname(url.hostname),
		url,
	};
}

export function validateNetworkTargetInScope(
	scope: SecurityScope,
	value: string,
): { ok: true } | { ok: false; error: string } {
	const parsed = parseNetworkTarget(value);
	if (typeof parsed === "string") {
		return { ok: false, error: parsed };
	}

	if (!isDomainAllowed(scope, parsed.hostname)) {
		return { ok: false, error: `Target '${value}' is outside scope.` };
	}

	return { ok: true };
}

function normalizeTargetValue(value: string): string {
	try {
		return new URL(value).toString();
	} catch {
		return value.trim();
	}
}

function targetMatchesReference(target: SecurityTarget, reference: string): boolean {
	const normalized = normalizeTargetValue(reference);
	if (target.id === reference || normalizeTargetValue(target.value) === normalized) {
		return true;
	}

	if (target.type === "web_application") {
		return target.origins.some((origin) => normalizeTargetValue(origin) === normalized);
	}

	return false;
}

export function isTargetReferenceInScope(scope: SecurityScope, reference: string): boolean {
	if (scope.targets.some((target) => targetMatchesReference(target, reference))) {
		return true;
	}

	const parsed = parseNetworkTarget(reference);
	return typeof parsed !== "string" && isDomainAllowed(scope, parsed.hostname);
}

export function findOutOfScopeTargetReferences(scope: SecurityScope, references: string[]): string[] {
	return references.filter((reference) => !isTargetReferenceInScope(scope, reference));
}
