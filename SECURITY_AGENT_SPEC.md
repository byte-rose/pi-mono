# Security Agent Fork Spec

## Status

Draft 1

## Goal

Create a security-focused fork of pi that keeps pi's reliability and extensibility while adding a first-class security runtime, security tooling, findings/reporting workflows, and explicit scope enforcement.

This fork should become its own npm-published product line, not just a collection of local extensions.

## Product Positioning

This fork is not a generic coding agent with a security prompt.
It is a security assessment agent platform built on pi's agent loop, tool calling, session management, and TUI/runtime primitives.

Primary use cases:
- white-box application security review
- black-box web assessment
- hybrid code + deployed target testing
- incident triage and evidence collection
- validation and remediation support

## Design Principles

1. Keep `packages/agent` generic and stable.
2. Keep pi's provider-native typed tool calling.
3. Add security capabilities as new packages and thin integration points.
4. Make scope, targets, runtime, artifacts, and reporting first-class.
5. Prefer typed tools over raw shell workflows.
6. Treat findings, notes, evidence, and reports as structured artifacts, not only chat text.
7. Make multi-agent orchestration optional and layered above the core loop.
8. Keep upstream mergeability where possible in `packages/agent`, `packages/ai`, and `packages/tui`.

## Non-Goals

- Replace pi's tool calling with XML prompt-based tool protocols.
- Rewrite `packages/agent` into a security-specific loop.
- Make the whole system depend on one giant security prompt.
- Force multi-agent execution for all workflows.
- Put all security behavior into ad hoc extensions without a package architecture.

## Best-of-Both-Worlds Direction

Keep from pi:
- `packages/agent`: stable loop, tool execution, event model
- `packages/coding-agent`: extension system, session model, TUI, skills, prompts, tool registry
- provider-native tool calling and typed schemas

Borrow from Strix:
- target/scope model
- security runtime abstraction
- security workflow modes
- notes/wiki/findings/reporting artifacts
- browser/proxy/python/terminal tool families
- vulnerability and technology skill taxonomy
- optional orchestration around specialized subagents

---

# 1. Package Strategy

## npm Scope and Product Rename

Use a dedicated npm scope for the fork.

The fork should rename the pi product line to `nyati` before first public release.
This rename should apply to:
- package names
- CLI binary names
- README and docs references
- examples and install instructions
- config directory naming, if intentionally changed
- npm publish targets

Recommended package naming:
- `@byte-rose/nyati-ai`
- `@byte-rose/nyati-agent-core`
- `@byte-rose/nyati-coding-agent`
- `@byte-rose/nyati-security-agent`
- `@byte-rose/nyati-security-runtime`
- `@byte-rose/nyati-security-tools`
- `@byte-rose/nyati-security-artifacts`
- `@byte-rose/nyati-security-reporting`
- `@byte-rose/nyati-security-skills`

Recommended CLI names:
- primary CLI: `nyati`
- optional security-specific alias later: `nyati-sec`

Publish target:
- publish the renamed `nyati` package line to npm under the chosen scope
- do not publish any public fork packages using the upstream `pi` naming once the rename is in effect

If branding changes again later, rename consistently before first stable public release.

## Package Layout

### Upstream-derived packages to retain
- `packages/ai`
- `packages/agent`
- `packages/tui`
- `packages/coding-agent`

These packages may keep their directory names initially for easier upstream merging, while their npm package names and CLI surface are renamed to the `nyati` brand.

### New packages to add
- `packages/security-agent`
  - top-level security CLI / SDK product
  - orchestrates runtime, scope, tools, prompts, skills, artifacts
- `packages/security-runtime`
  - runtime abstraction and implementations
  - Docker runtime first
  - SSH/Kubernetes later
- `packages/security-tools`
  - typed tool definitions and helpers
  - browser, proxy, python, terminal, scanner wrappers, findings tools
- `packages/security-artifacts`
  - structured models and persistence for findings, evidence, notes, target maps
- `packages/security-reporting`
  - reporting pipeline, severity, dedupe, export formats
- `packages/security-skills`
  - packaged security skills, prompts, presets, themes, default extensions

## Ownership Boundaries

### `packages/agent`
Only generic primitives if absolutely necessary:
- session-scoped services hooks
- runtime lifecycle hook points
- generic artifact entry extension points

### `packages/coding-agent`
May receive integration primitives needed by the security product:
- richer tool render hooks
- session service wiring
- extension/runtime bootstrapping improvements
- more explicit active mode / preset support

### `packages/security-*`
All security-specific behavior should live here.

---

# 2. Core Domain Model

## 2.1 Security Scope Model

This must be first-class and runtime-enforced.
It must not exist only as prompt text.

### `SecurityScope`

```ts
interface SecurityScope {
  engagementId: string;
  mode: AssessmentMode;
  scanMode: ScanMode;
  executionMode: ExecutionMode;
  targets: SecurityTarget[];
  exclusions: ScopeExclusion[];
  allowedActions: AllowedAction[];
  filesystem: FilesystemPolicy;
  network: NetworkPolicy;
  reporting: ReportingPolicy;
  metadata: {
    source: "cli" | "config" | "session" | "api";
    verified: boolean;
    createdAt: number;
    updatedAt: number;
  };
}
```

### `AssessmentMode`
- `blackbox`
- `whitebox`
- `hybrid`

### `ScanMode`
- `quick`
- `standard`
- `deep`

### `ExecutionMode`
- `read_only`
- `validate`
- `exploit`
- `remediate`

### `SecurityTarget`

```ts
type SecurityTarget =
  | RepositoryTarget
  | LocalCodeTarget
  | WebApplicationTarget
  | IpAddressTarget
  | ApiCollectionTarget;
```

#### `RepositoryTarget`
```ts
interface RepositoryTarget {
  id: string;
  type: "repository";
  value: string;            // repo URL or slug
  workspacePath?: string;
  defaultBranch?: string;
}
```

#### `LocalCodeTarget`
```ts
interface LocalCodeTarget {
  id: string;
  type: "local_code";
  value: string;            // source path
  workspacePath: string;
}
```

#### `WebApplicationTarget`
```ts
interface WebApplicationTarget {
  id: string;
  type: "web_application";
  value: string;            // origin or URL
  origins: string[];
  authProfileId?: string;
}
```

#### `IpAddressTarget`
```ts
interface IpAddressTarget {
  id: string;
  type: "ip_address";
  value: string;
  ports?: number[];
}
```

#### `ApiCollectionTarget`
```ts
interface ApiCollectionTarget {
  id: string;
  type: "api_collection";
  value: string;            // file path or collection id
  workspacePath?: string;
}
```

## 2.2 Policy Model

### `FilesystemPolicy`
- readable roots
- writable roots
- blocked secret paths
- artifact directories

### `NetworkPolicy`
- allowed domains
- denied domains
- allowed CIDRs
- denied CIDRs
- browser-enabled flag
- proxy-enabled flag

### `AllowedAction`
- `read_files`
- `write_files`
- `run_commands`
- `network_scan`
- `http_test`
- `browser_test`
- `modify_code`
- `create_reports`

## 2.3 Enforcement Points

Scope must be enforced at:
- tool argument validation
- `bash` wrapping / replacement
- runtime network policy
- file read/write tool hooks
- browser/proxy target restrictions
- report target association
- subagent delegation

---

# 3. Runtime Architecture

## 3.1 Runtime Abstraction

Borrow the shape from Strix, but implement it in TypeScript and keep it session-scoped.

### `SecurityRuntime`

```ts
interface SecurityRuntime {
  createWorkspace(input: CreateWorkspaceInput): Promise<WorkspaceHandle>;
  destroyWorkspace(workspaceId: string): Promise<void>;
  getTerminal(workspaceId: string): Promise<TerminalHandle>;
  getPython(workspaceId: string): Promise<PythonHandle>;
  getBrowser(workspaceId: string): Promise<BrowserHandle | undefined>;
  getProxy(workspaceId: string): Promise<ProxyHandle | undefined>;
  syncTargets(workspaceId: string, targets: SecurityTarget[]): Promise<void>;
}
```

## 3.2 First Runtime Implementation

### Phase 1 runtime target
- `DockerSecurityRuntime`

Responsibilities:
- provision workspace
- copy/mount local repositories
- start supporting services
- enforce network/filesystem policy where possible
- provide stable handles to tools

## 3.3 Supporting Services

Add service abstractions for:
- terminal execution
- Python execution
- browser automation
- HTTP proxy / request replay
- scanner wrapper execution
- artifact storage

---

# 4. Artifact Architecture

## 4.1 Artifact Types

Create a structured artifact model.

### Required Phase 1 artifacts
- `Finding`
- `Evidence`
- `Note`
- `TargetMap`
- `RunSummary`

### Later artifacts
- `RequestReplay`
- `AttackPath`
- `CredentialObservation`
- `PatchCandidate`
- `RemediationTask`

## 4.2 Finding Model

```ts
interface Finding {
  id: string;
  title: string;
  category: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  confidence: "low" | "medium" | "high";
  status: "candidate" | "validated" | "reported" | "fixed" | "closed";
  targets: string[];
  evidenceIds: string[];
  cwe?: string;
  cve?: string;
  cvss?: string;
  summary: string;
  technicalAnalysis: string;
  impact: string;
  remediation: string;
  createdAt: number;
  updatedAt: number;
}
```

## 4.3 Evidence Model

```ts
interface Evidence {
  id: string;
  findingId?: string;
  type: "http" | "file" | "terminal" | "browser" | "image" | "note" | "diff";
  title: string;
  content: unknown;
  targets: string[];
  createdAt: number;
}
```

## 4.4 Persistence

Persist artifacts outside normal assistant text history.

Recommended storage shape:
- session-linked JSONL or JSON documents under a security run directory
- summary entries may be referenced in session messages
- full artifacts remain structured and replayable

---

# 5. Reporting Architecture

Reporting moves into Phase 1.
This is a required change from the earlier phased plan.

## 5.1 Reporting in Phase 1

Add a first-class reporting layer immediately.

### Required Phase 1 reporting capabilities
- create/update/list findings
- attach evidence to findings
- create draft report entries
- dedupe similar findings
- severity and CVSS helpers
- export Markdown and JSON reports
- TUI rendering for findings and report status

## 5.2 Package Ownership

### `packages/security-reporting`
Responsibilities:
- finding schemas
- severity helpers
- CVSS helpers
- dedupe logic
- report generation
- export adapters

### `packages/security-agent`
Responsibilities:
- register reporting tools
- render findings in TUI
- connect reports to sessions and runs

## 5.3 Phase 1 Reporting Tools

Required tools:
- `create_finding`
- `update_finding`
- `list_findings`
- `attach_evidence`
- `create_note`
- `update_note`
- `list_notes`
- `export_report`

Optional in Phase 1 if time allows:
- `calculate_cvss`
- `dedupe_findings`

## 5.4 TUI Expectations

Required renderers:
- finding card renderer
- evidence summary renderer
- report export status renderer
- scope summary renderer

---

# 6. Tool Architecture

## 6.1 Keep Pi Tool Contract

Do not replace pi's typed provider-native tool system.
Use `registerTool()` and session/runtime services.

## 6.2 Tool Families

### Foundation tools
- scoped `read`
- scoped `write`
- scoped `edit`
- scoped `bash`
- `grep`
- `find`
- `ls`

### Security runtime tools
- `terminal_exec`
- `python_exec`
- `browser_action`
- `http_request`
- `http_replay`
- `proxy_list_requests`
- `proxy_view_request`
- `proxy_sitemap`

### Scanner wrappers
- `semgrep_scan`
- `nuclei_scan`
- `httpx_probe`
- `nmap_scan`
- `ffuf_scan`
- `trivy_fs_scan`
- `gitleaks_scan`

### Artifact/reporting tools
- `create_finding`
- `update_finding`
- `attach_evidence`
- `create_note`
- `update_note`
- `list_findings`
- `export_report`

### Coordination tools
- `delegate_task`
- `list_subagents`
- `share_artifact`

## 6.3 Tool Policy

- Prefer typed tools over shell one-liners.
- Allow `bash` for glue and environment inspection, not as the only security interface.
- Every network-capable tool must receive scope-aware validation.
- Every file mutation tool must respect execution mode and allowed paths.

---

# 7. Skills and Prompt Taxonomy

## 7.1 Use Pi Skills, Borrow Strix Taxonomy

Package the following skill directories in `packages/security-skills`:
- `skills/scan-modes/`
- `skills/vulnerabilities/`
- `skills/frameworks/`
- `skills/protocols/`
- `skills/tooling/`
- `skills/cloud/`
- `skills/reporting/`
- `skills/playbooks/`

## 7.2 Initial Skill Set

### Scan modes
- `quick`
- `standard`
- `deep`

### Vulnerabilities
- `idor`
- `sqli`
- `ssrf`
- `xss`
- `xxe`
- `rce`
- `csrf`
- `race-conditions`
- `business-logic`
- `jwt-auth`

### Tooling
- `semgrep`
- `nuclei`
- `httpx`
- `nmap`
- `ffuf`
- `trivy`
- `gitleaks`

### Reporting
- `write-finding`
- `severity-triage`
- `evidence-checklist`

---

# 8. Strix-to-Pi Mapping

## 8.1 Architecture Mapping

| Strix Concept | Strix Location | Pi Fork Equivalent |
|---|---|---|
| Base agent loop | `strix/agents/base_agent.py` | keep `packages/agent`; add security orchestration above it |
| Target/scope injection | `strix_agent.py`, `system_prompt.jinja` | `SecurityScopeService` + prompt section + tool enforcement |
| Docker runtime | `runtime/docker_runtime.py` | `packages/security-runtime` |
| Tool registry | `tools/registry.py` | keep pi tool registry and extension tools |
| Tool execution routing | `tools/executor.py` | runtime-backed typed tools |
| Notes/wiki | `tools/notes/notes_actions.py` | `packages/security-artifacts` + tools |
| Finding/reporting | `tools/reporting/reporting_actions.py` | `packages/security-reporting` + TUI renderers |
| Load skill | `tools/load_skill/*` | reuse pi skills and prompt taxonomy |
| Agent graph | `tools/agents_graph/*` | optional orchestration package, not core loop |
| Browser/proxy/python/terminal | `tools/browser`, `tools/proxy`, `tools/python`, `tools/terminal` | `packages/security-tools` + `packages/security-runtime` |
| Custom streaming parser | `interface/streaming_parser.py` | do not adopt; keep provider-native tool calls |

## 8.2 Tool Mapping

| Strix Tool | Proposed Pi Fork Tool | Notes |
|---|---|---|
| `terminal_execute` | `terminal_exec` | backed by runtime terminal handle |
| `python_action` | `python_exec` | persistent interpreter per workspace/session |
| `browser_action` | `browser_action` | runtime-backed browser tool |
| `send_request` | `http_request` | typed HTTP request tool |
| `repeat_request` | `http_replay` | replay captured request with modifications |
| `list_requests` | `proxy_list_requests` | query proxy request store |
| `view_request` | `proxy_view_request` | inspect request/response |
| `list_sitemap` | `proxy_sitemap` | attack surface/sitemap viewer |
| `create_vulnerability_report` | `create_finding` + `export_report` | split live finding creation from report export |
| `create_note` / `update_note` | `create_note` / `update_note` | keep concept, pi-native implementation |
| `load_skill` | pi skill system | use explicit `/skill:*` and auto-load guidance |
| `create_agent` | `delegate_task` | optional later-phase orchestration |
| `wait_for_message` | queued subagent/session model | optional later phase |
| `think` | custom reasoning helper or rely on model | optional; not required in phase 1 |

---

# 9. Implementation Plan

## Phase 0: Fork Foundation and Naming

### Objectives
- establish package scope and branding
- rename the pi product line to `nyati`
- prepare the fork for npm publication
- preserve upstream mergeability boundaries
- create spec-backed roadmap

### Deliverables
- rename npm package scopes for forked publish targets
- rename the product and primary CLI from `pi` to `nyati`
- define npm publish targets for the `nyati` package line
- update docs and install examples to use `nyati`
- decide whether config directories remain `.pi` / `~/.pi/agent` temporarily for compatibility or move to `.nyati` / `~/.nyati/agent`
- add `SECURITY_AGENT_SPEC.md`
- create package skeletons

### Required rename checklist
- rename package names in all affected `package.json` files
- rename CLI bin entry points from `pi` to `nyati`
- update import specifiers across the monorepo to the new package names
- update README, docs, examples, changelogs, and install snippets
- update publishing metadata and repository package references
- decide and implement config directory migration strategy
- verify that `npm publish` targets the `nyati` names only

### Package skeletons to create
- `packages/security-agent`
- `packages/security-runtime`
- `packages/security-tools`
- `packages/security-artifacts`
- `packages/security-reporting`
- `packages/security-skills`

---

## Phase 1: Scope, Runtime Foundation, Reporting, Artifact Core

Reporting is intentionally moved into Phase 1.

### Objectives
- make scope first-class
- make runtime abstraction first-class
- make findings/notes/reporting first-class
- establish minimum security mode on top of pi

### Deliverables

#### 1. Scope core
- implement `SecurityScope` model
- implement target parsers for local code, repo, URL, IP
- implement scope validation helpers
- inject scope summary into system prompt
- enforce scope in file/network-sensitive tools

#### 2. Runtime core
- implement `SecurityRuntime` interfaces
- implement `DockerSecurityRuntime`
- add workspace lifecycle management
- add terminal and Python handles

#### 3. Artifact core
- implement `Finding`, `Evidence`, `Note`, `RunSummary`
- implement artifact persistence layer
- connect artifacts to session/run IDs

#### 4. Reporting core
- implement `packages/security-reporting`
- add `create_finding`, `update_finding`, `list_findings`, `attach_evidence`, `export_report`
- add Markdown + JSON exporters
- add basic severity and CVSS helpers
- add finding list and finding card renderers

#### 5. Security mode integration
- add `packages/security-agent` bootstrap
- add read-mostly default mode
- default tool policy: scoped `read`, `grep`, `find`, `ls`, restricted `bash`
- optional `/engage` or mode switch to enable mutation/remediation

### File/Package Directions

#### `packages/security-agent`
- CLI entry
- runtime/session bootstrap
- scope loading
- active tool set initialization
- reporting tool registration

#### `packages/security-runtime`
- `src/runtime.ts`
- `src/docker-runtime.ts`
- `src/terminal.ts`
- `src/python.ts`

#### `packages/security-artifacts`
- `src/types.ts`
- `src/store.ts`
- `src/findings.ts`
- `src/notes.ts`

#### `packages/security-reporting`
- `src/cvss.ts`
- `src/dedupe.ts`
- `src/export/markdown.ts`
- `src/export/json.ts`

#### `packages/coding-agent`
Minimal changes only if needed for:
- session-scoped service registration
- security render slots
- clean integration hooks for artifact stores

---

## Phase 2: Security Tool Surface Mapping

### Objectives
- map Strix tool families into typed pi-native tools
- reduce dependence on raw `bash`
- establish security TUI flows

### Deliverables

#### Runtime-backed tools
- `terminal_exec`
- `python_exec`
- `http_request`
- `http_replay`
- `proxy_list_requests`
- `proxy_view_request`
- `proxy_sitemap`

#### Scanner wrappers
- `semgrep_scan`
- `nuclei_scan`
- `httpx_probe`
- `nmap_scan`
- `trivy_fs_scan`
- `gitleaks_scan`

#### TUI renderers
- HTTP exchange renderer
- scanner summary renderer
- evidence renderer
- target scope widget

### Mapping Rules
- if Strix tool is a domain operation, create a typed tool
- if Strix tool is artifact-oriented, attach it to `security-artifacts` / `security-reporting`
- if Strix tool is runtime-oriented, attach it to `security-runtime`
- do not proxy everything through one generic terminal tool

---

## Phase 3: Skills, Scan Modes, Workflow Presets

### Objectives
- build the methodology layer
- create reusable scan/playbook flows

### Deliverables
- `packages/security-skills`
- scan-mode skill bundles
- vulnerability skill bundles
- workflow prompt templates
- execution presets:
  - quick black-box
  - standard white-box
  - deep hybrid
  - remediation

---

## Phase 4: Optional Orchestration Layer

### Objectives
- add specialized delegated workflows without contaminating the core loop

### Deliverables
- `delegate_task`
- isolated subagent sessions or subprocesses
- artifact-sharing model
- target-focused fan-out strategies
- per-finding validator agents

### Constraint
This phase must remain optional and layered. It must not become a prerequisite for stable single-agent operation.

---

## Phase 5: Remediation and Advanced Reporting

### Objectives
- add security fix workflows and richer exports

### Deliverables
- remediation mode
- patch candidate artifacts
- fix verification tools
- SARIF exporter
- HTML report exporter
- evidence bundle packaging

---

# 10. Clear First Execution Order

## Immediate next implementation order

1. rename package line from `pi` to `nyati` and define npm publish targets
2. package scope and package skeletons
3. `SecurityScope` model and validation
4. `SecurityRuntime` abstraction and Docker implementation
5. artifact store
6. reporting package and reporting tools
7. security-agent bootstrap package
8. scoped default tool set
9. typed runtime-backed tools
10. skills and presets
11. optional orchestration

## Hard rules during implementation

- Do not redesign pi tool calling.
- Do not move security logic into `packages/agent` unless it is a generic primitive.
- Do not make findings live only in assistant text.
- Do not make browser/proxy/python features ad hoc extension demos only; they should land in proper packages.
- Do not make scope advisory only; it must be enforced.

---

# 11. Success Criteria

The fork is on the right path when:

1. a scan can be started with explicit typed targets and explicit scope
2. scope is enforced across tools and runtime
3. findings and evidence are stored as artifacts
4. reports can be exported without scraping assistant prose
5. security workflows mostly use typed tools, not raw bash
6. pi reliability remains intact for single-agent runs
7. upstream merges into `packages/agent`, `packages/ai`, and `packages/tui` remain manageable

---

# 12. Initial Work Breakdown

## Track A: Package and publish foundation
- rename package scopes
- create package manifests
- wire workspaces

## Track B: Scope and runtime
- implement models
- implement Docker runtime
- wire bootstrap

## Track C: Artifacts and reporting
- implement findings/evidence/notes store
- implement exporters
- implement TUI renderers

## Track D: Tool surface
- terminal/python/http/proxy/scanner wrappers

## Track E: Skills and presets
- vulnerability and scan-mode skill bundles

## Track F: Orchestration
- optional delegated task execution

---

# 13. Recommended First Code Targets

When implementation starts, begin here:

1. create new package directories under `packages/`
2. wire root workspace `package.json`
3. add `packages/security-artifacts/src/types.ts`
4. add `packages/security-reporting/src/` helpers and exporters
5. add `packages/security-runtime/src/runtime.ts`
6. add `packages/security-runtime/src/docker-runtime.ts`
7. add `packages/security-agent/src/` bootstrap and integration
8. add minimal `packages/security-tools/src/` reporting and runtime-backed tools

This ordering gets the foundation, scope, runtime, and reporting done before the broader tool surface.
