// packages/security-runtime/src/runtime.ts

export interface WorkspaceHandle {
	workspaceId: string;
	containerId: string;
	workspacePath: string;
}

export interface CreateWorkspaceInput {
	agentId: string;
	localSources?: Array<{ sourcePath: string; workspaceSubdir?: string }>;
	envVars?: Record<string, string>;
	capAdd?: string[];
}

export interface ExecOptions {
	workingDir?: string;
	timeoutMs?: number;
}

export interface ExecResult {
	stdout: string;
	stderr: string;
	exitCode: number;
}

export interface SecurityRuntime {
	createWorkspace(input: CreateWorkspaceInput): Promise<WorkspaceHandle>;
	destroyWorkspace(workspaceId: string): Promise<void>;
	syncTargets(workspaceId: string, targets: unknown[]): Promise<void>;
	execInContainer(workspaceId: string, command: string, options?: ExecOptions): Promise<ExecResult>;
	cleanup(): void;
}
