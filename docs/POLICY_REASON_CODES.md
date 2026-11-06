# AI Forge — Deterministic Policy Engine & Reason Codes

The Policy Enforcement Point (`src/lib/domain/policy/engine.ts`) evaluates every proposed capability invocation deterministically **before** any adapter or tool is called.

## 1. Fundamental Invariants

1. **No LLM Authorization**: The model may propose a tool call, but the PEP evaluates structured `PolicyInput` against the active `PolicyBundle` and `AgentLockfile`.
2. **Deny-by-Default**: If no explicit allow rule matches after all guardrails pass, the engine returns `decision: "deny"` with `reasonCode: "default_deny"`.
3. **Cryptographic Pinning**: Every `PolicyDecision` records the SHA-256 `policyDigest` of the active policy bundle.

## 2. Ordered Rule Evaluation Precedence (Rules 1 → 9)

| Precedence | Rule ID | Condition | Decision | Reason Code |
|---|---|---|---|---|
| **1** | `R1_CAPABILITY_DECLARED` | `!capabilityDeclared \|\| !actionDeclared` | `deny` | `capability_not_declared` |
| **2** | `R2_RESOURCE_SCOPE` | `!resourceAllowed` (fails `allowedResources` glob) | `deny` | `resource_out_of_scope` |
| **3** | `R3_DATA_CLASSIFICATION` | `dataClassification > agentMaxDataClassification` | `deny` | `data_classification_exceeded` |
| **4** | `R4_EGRESS_CONTROL` | `egressViolation === true` | `deny` | `egress_not_allowed` |
| **5** | `R5_BUDGET_GUARD` | `currentCostUsd >= agentMaxCostUsd \|\| currentToolCalls >= agentMaxToolCalls` | `deny` | `budget_exceeded` |
| **6** | `R6_DELEGATION_DEPTH` | `currentDelegationDepth > agentMaxDelegationDepth` | `deny` | `delegation_depth_exceeded` |
| **7** | `R7_DESTRUCTIVE_BLOCK` | `effect === "delete"` | `deny` | `destructive_action_blocked` |
| **8** | `R8_WRITE_APPROVAL` | `effect === "write"` or `effect === "external_call"` or `environment === "production"` with elevated risk | `approval_required` | `write_requires_approval` |
| **9** | `R9_READ_WITHIN_CONTRACT` | `effect === "read"` and Rules 1–8 passed | `allow` | `read_within_contract` |
| **Fallback** | `R0_DEFAULT_DENY` | Any other unclassified effect or state | `deny` | `default_deny` |

## 3. Testing & Interactive Verification

- **Unit Tests**: `__tests__/unit/policy-engine.test.ts`
- **API Endpoint**: `POST /api/policies/evaluate` (supports single `PolicyInput` or `{ runAllRules: true }` to execute all 9 rules at once).
- **UI Console**: Navigate to `/policies` (**Policy Center**) to test any rule with 1-click presets or run the 9-rule regression suite.

