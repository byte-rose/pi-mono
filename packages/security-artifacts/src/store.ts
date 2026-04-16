import { appendFile, mkdir, readFile } from "node:fs/promises";
import { join } from "node:path";
import { v4 as uuidv4 } from "uuid";
import type { Evidence, Finding, Note } from "./types.js";

type StoreOp = "create" | "update" | "delete";

interface StoreEvent {
	timestamp: string;
	op: StoreOp;
	kind: "finding" | "evidence" | "note";
	id: string;
	data?: unknown;
}

export class ArtifactStore {
	private readonly runDir: string;
	private findings = new Map<string, Finding>();
	private evidence = new Map<string, Evidence>();
	private notes = new Map<string, Note>();
	private loaded = false;

	constructor(runDir: string) {
		this.runDir = runDir;
	}

	private get logPath(): string {
		return join(this.runDir, "artifacts.jsonl");
	}

	private async ensureDir(): Promise<void> {
		await mkdir(this.runDir, { recursive: true });
	}

	private async load(): Promise<void> {
		if (this.loaded) return;
		this.loaded = true;
		try {
			const raw = await readFile(this.logPath, "utf-8");
			for (const line of raw.split("\n")) {
				if (!line.trim()) continue;
				try {
					const event = JSON.parse(line) as StoreEvent;
					this.applyEvent(event);
				} catch {
					// corrupt line — skip
				}
			}
		} catch {
			// file doesn't exist yet — fine
		}
	}

	private applyEvent(event: StoreEvent): void {
		if (event.kind === "finding") {
			if (event.op === "delete") {
				this.findings.delete(event.id);
			} else if (event.data) {
				const existing = this.findings.get(event.id) ?? ({} as Finding);
				this.findings.set(event.id, { ...existing, ...(event.data as Partial<Finding>), id: event.id });
			}
		} else if (event.kind === "evidence") {
			if (event.op === "delete") {
				this.evidence.delete(event.id);
			} else if (event.data) {
				const existing = this.evidence.get(event.id) ?? ({} as Evidence);
				this.evidence.set(event.id, { ...existing, ...(event.data as Partial<Evidence>), id: event.id });
			}
		} else if (event.kind === "note") {
			if (event.op === "delete") {
				this.notes.delete(event.id);
			} else if (event.data) {
				const existing = this.notes.get(event.id) ?? ({} as Note);
				this.notes.set(event.id, { ...existing, ...(event.data as Partial<Note>), id: event.id });
			}
		}
	}

	private async appendEvent(event: StoreEvent): Promise<void> {
		await this.ensureDir();
		await appendFile(this.logPath, `${JSON.stringify(event)}\n`, "utf-8");
	}

	async appendFinding(data: Omit<Finding, "id" | "createdAt" | "updatedAt">): Promise<string> {
		await this.load();
		const id = uuidv4();
		const now = Date.now();
		const finding: Finding = { ...data, id, createdAt: now, updatedAt: now };
		this.findings.set(id, finding);
		await this.appendEvent({ timestamp: new Date().toISOString(), op: "create", kind: "finding", id, data: finding });
		return id;
	}

	async updateFinding(id: string, patch: Partial<Omit<Finding, "id" | "createdAt">>): Promise<void> {
		await this.load();
		const existing = this.findings.get(id);
		if (!existing) throw new Error(`Finding ${id} not found`);
		const updated: Finding = { ...existing, ...patch, updatedAt: Date.now() };
		this.findings.set(id, updated);
		await this.appendEvent({ timestamp: new Date().toISOString(), op: "update", kind: "finding", id, data: updated });
	}

	async listFindings(): Promise<Finding[]> {
		await this.load();
		return Array.from(this.findings.values()).sort((a, b) => a.createdAt - b.createdAt);
	}

	async getFinding(id: string): Promise<Finding | undefined> {
		await this.load();
		return this.findings.get(id);
	}

	async appendEvidence(data: Omit<Evidence, "id" | "createdAt">): Promise<string> {
		await this.load();
		const id = uuidv4();
		const evidence: Evidence = { ...data, id, createdAt: Date.now() };
		this.evidence.set(id, evidence);
		await this.appendEvent({
			timestamp: new Date().toISOString(),
			op: "create",
			kind: "evidence",
			id,
			data: evidence,
		});
		return id;
	}

	async listEvidence(findingId?: string): Promise<Evidence[]> {
		await this.load();
		const all = Array.from(this.evidence.values());
		return findingId ? all.filter((e) => e.findingId === findingId) : all;
	}
}
