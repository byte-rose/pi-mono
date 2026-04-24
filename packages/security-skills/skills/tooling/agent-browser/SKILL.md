---
name: agent-browser
description: Use the Agent Browser CLI-backed browser_action tool as the default workflow for browser-based recon, authenticated flows, and evidence capture on scoped web targets.
---

# Agent Browser for Security Testing

Use `browser_action`, backed by Agent Browser, as the default interface for browser-side testing whenever the target is a web application and browser workflows are enabled in scope.

## Operator Prerequisite

Install the Agent Browser CLI on the machine running the security session:

`npm i -g agent-browser && agent-browser install`

This security extension exposes a typed `browser_action` tool. Use that tool directly rather than trying to shell out manually. If the CLI is missing, the tool will try to install it automatically by default; if that fails, it will return the exact install command to run.

## Startup Workflow

1. Use `browser_action` with `open` on the scoped target URL.
2. Use `browser_action` with `snapshot` to inspect interactive elements and capture fresh refs.
3. Use `browser_action` with `click`, `fill`, `press`, and `wait` to move through the workflow.
4. Re-snapshot after any navigation or DOM change before using more refs.
5. Keep one named browser session per engagement or target so state, screenshots, and repro steps stay attributable.

## Use `browser_action` For

- Rendered pages, SPAs, and client-side navigation
- Authentication, MFA, role switching, and multi-step business flows
- DOM-aware recon, form interaction, and screenshot capture
- Business-logic testing where sequence and state matter
- Reproducing findings with user-visible evidence

## Security Workflow Overlay

- Start from login, account, billing, admin, upload, and integration surfaces
- Re-snapshot after every navigation or DOM change before using another element ref
- Preserve named sessions so auth state can be reused across roles or test accounts
- Capture screenshots before and after every privileged action, unexpected state transition, or policy bypass

## Evidence Expectations

For each confirmed issue, capture:

- exact page URL and user/role context
- screenshots of the vulnerable state and the resulting impact
- minimal, ordered reproduction steps

## Local Customization

If the local browser workflow needs more security-specific direction, extend this overlay skill and keep `browser_action` as the primary interface.
