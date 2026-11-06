# AI Forge — Threat Model & Regulatory Alignment

Aligned with **OWASP Top 10 for Agentic Applications (2026)**, **OWASP Top 10 for LLM Applications (2025)**, **NIST AI RMF**, and **STRIDE**.

## 1. OWASP Agentic Top 10 (2026) Mitigation Matrix

| Threat ID | Threat Name | Attack Scenario | AI Forge Architectural Control | Verification |
|---|---|---|---|---|
| **ASI01** | **Agent Goal Hijack** (Indirect Prompt Injection) | Malicious `README.md` or PR description instructs the auditor to ignore SQLi, read secrets, and exfiltrate data. | Untrusted repo data is wrapped in data-only envelopes; PEP blocks `secret:read` (`capability_not_declared`) and `network:egress` (`egress_not_allowed`) regardless of model output. | `INJECTION-001` eval gate + `orchestrateSecurityPrAudit(fixture: 'injection')` |
| **ASI02** | **Tool Misuse & Scope Creep** | User or prompt asks the auditor to merge a PR (`pull-request:merge`) or access an unapproved repo (`evil-org/secrets`). | Every capability contract specifies allowed actions and `allowedResources` globs (`org-approved/*`). Out-of-scope calls are denied pre-invocation (`resource_out_of_scope`, `capability_not_declared`). | `SCOPE-001` & `RESOURCE-001` eval gates |
| **ASI03** | **Identity & Privilege Abuse** (Confused Deputy) | Agent reuses a broad static token across runs or escalates privileges in sub-calls. | `DemoCredentialBroker` issues ephemeral, run-scoped `DelegatedCredential` tokens bound to `(runId, releaseDigest, capability, action, resource)` with short TTL and `maxDelegationDepth: 0`. | `__tests__/security/tenant-and-controls.test.ts` |
| **ASI04** | **Supply Chain & Mutable Agent Drift** | Silent prompt edits, unreviewed tool additions, or policy drift change production behavior without audit. | `AgentLockfile` pins SHA-256 digests of the manifest, capability contracts, policy bundle, and eval suite into an immutable `releaseDigest`. | `buildLockfile` + Release Detail SHA-256 verifier |
| **ASI05** | **Unbounded Autonomy & Side Effects** | Agent publishes comments, modifies code, or deletes resources without human review. | `effect: delete` is strictly denied (`destructive_action_blocked`); `effect: write` halts execution and creates an `ApprovalRequest` (`write_requires_approval`). | `WRITE-001` eval gate + `/approvals` workflow |
| **ASI06** | **Resource & Cost Exhaustion (Denial of Wallet)** | Runaway tool loop exhausts token/API budgets. | `BudgetTracker` and PEP rule `R5_BUDGET_GUARD` enforce `maxRunSeconds`, `maxToolCalls`, and `maxCostUsd` before every tool call. | `BUDGET-001` eval gate |
| **ASI07** | **Evidence Repudiation & Log Tampering** | Post-hoc modification of run outputs, findings, or policy logs to hide a failure or security incident. | `EvidenceBundleBuilder` computes a canonical SHA-256 `bundleDigest` over all decisions, tool calls, artifacts, and costs; `verifyEvidenceBundle` detects any single-byte modification. | `/evidence` Tamper-Detection Simulator + `__tests__/unit/evidence-and-diff.test.ts` |

## 2. STRIDE Analysis

- **Spoofing**: Mitigated via NextAuth session context, RBAC (`owner | admin | operator | viewer | auditor`), and run-bound `DelegatedCredential` tokens.
- **Tampering**: Mitigated via canonical JSON SHA-256 digests on `AgentCommit`, `AgentLockfile`, `PolicyBundle`, and `EvidenceBundle`.
- **Repudiation**: Mitigated via append-only `AuditLog`, `RunEvent` sequences, and signed `ApprovalRequest` decisions with mandatory justification.
- **Information Disclosure**: Mitigated via organization tenancy checks (`assertOrganizationAccess`), automatic secret redaction (`redactSecrets`), and manifest secret-scanning validation.
- **Denial of Service**: Mitigated via multi-dimensional rate limiting (`organizationId:userId:endpoint` in `src/lib/security/rate-limit.ts`) and per-run `BudgetTracker`.
- **Elevation of Privilege**: Mitigated via deterministic PEP (`src/lib/domain/policy/engine.ts`) completely independent of the LLM, plus `maxDelegationDepth: 0`.

