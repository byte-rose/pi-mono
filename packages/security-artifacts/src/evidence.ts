import type { Evidence } from "./types.js";

export type { Evidence };

export function validateEvidence(fields: { title: string; content: unknown }): string[] {
	const errors: string[] = [];
	if (!fields.title?.toString().trim()) errors.push("title cannot be empty");
	if (fields.content === null || fields.content === undefined) errors.push("content cannot be null");
	return errors;
}
