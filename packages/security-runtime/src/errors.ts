// packages/security-runtime/src/errors.ts
export class SandboxInitializationError extends Error {
	constructor(
		public readonly reason: string,
		public readonly hint: string,
	) {
		super(`${reason}: ${hint}`);
		this.name = "SandboxInitializationError";
	}
}
