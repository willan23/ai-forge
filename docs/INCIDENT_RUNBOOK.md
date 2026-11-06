# AI Forge — Operational Incident Runbook

This runbook defines the step-by-step response procedures for Security Operations (SecOps) and AI Platform Engineers operating **AI Forge**.

---

## 1. Emergency Kill Switch Activation (Agent Containment)

**When to use**: Suspected prompt injection bypass, anomalous tool call rate, unexpected external connector behavior, or compromised upstream repository.

### Via UI Console
1. Navigate to **`/agents`** or **`/agents/[agentId]`**.
2. Click **`Activate Kill Switch`** (turns badge red: `KILL SWITCH ON`).
3. Verify on **`/` (Overview)** that `Active Kill Switches` incremented and any new run attempt returns `kill_switch_active`.

### Via API
```bash
curl -X PATCH http://localhost:3000/api/agents/agent_security_pr_auditor \
  -H "Content-Type: application/json" \
  -d '{"killSwitch": true}'
```

**Effect**:
- Immediately blocks `startRunService` and `orchestrateSecurityPrAudit` with `kill_switch_active`.
- Records `agent.killswitch.enabled` in `AuditLog` with actor and timestamp.

---

## 2. Delegated Credential Revocation

**When to use**: A run is cancelled mid-flight, or a capability adapter reports anomalous activity.

1. Ephemeral credentials issued by `DemoCredentialBroker` have a strict short TTL (default 60 seconds) and are bound to `(runId, releaseDigest, capability, action, resource)`.
2. Call `broker.revokeForRun(runId)` or cancel the run. Any subsequent adapter call with that credential fails immediately with `credential_revoked` or `credential_expired`.

---

## 3. Cryptographic Evidence Preservation & Tamper Verification

**When to use**: Post-incident forensics, regulatory audit, or suspected tampering of run outputs.

1. Export the canonical Evidence Bundle JSON:
   ```bash
   curl -s http://localhost:3000/api/agents/agent_security_pr_auditor/runs/<runId>/evidence > evidence_<runId>.json
   ```
2. Verify cryptographic integrity via API or `/evidence` console:
   ```bash
   curl -X POST http://localhost:3000/api/evidence/verify \
     -H "Content-Type: application/json" \
     -d "{\"bundle\": $(cat evidence_<runId>.json)}"
   ```
3. Confirm `valid: true`, `tampered: false`, and that all checks (`schema_validation`, `canonical_bundle_digest`, `lockfile_digest_verification`, `policy_digest_consistency`) pass.

---

## 4. Release Rollback / Pinning Known-Good Digest

**When to use**: A newly promoted release exhibits degraded evaluation metrics or false positives.

1. Navigate to **`/agents/[agentId]` → `Releases` tab**.
2. Identify the previous known-good `releaseDigest` (`sha256:...`).
3. Pin execution triggers to the known-good `releaseId` / `releaseDigest` when invoking `POST /api/agents/[agentId]/runs`.
4. Create a revert `ChangeProposal` in **`/agents/[agentId]/manifest`** and run the 7-scenario evaluation gate before publishing a new release.

