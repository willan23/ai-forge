"""
aiforge_sdk — Official Universal Agent Governance SDK for Python 3.10+
Zero external dependencies (uses standard library urllib.request & json).
Compatible with LangChain, CrewAI, OpenAI Agents SDK, AutoGen, and FastMCP.
"""

from __future__ import annotations
import functools
import json
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Literal, Optional


class AiForgePolicyDeniedError(PermissionError):
    """Raised when AI Forge's 9-Rule PEP denies or holds a tool call for HITL approval."""

    def __init__(self, decision: str, reason_code: str, resource: str, explanation: str = "") -> None:
        self.decision = decision
        self.reason_code = reason_code
        self.resource = resource
        self.explanation = explanation
        super().__init__(
            f"AI Forge PEP blocked tool execution ({decision}: {reason_code}) on resource '{resource}'"
            + (f" — {explanation}" if explanation else "")
        )


class AiForgeGatewayClient:
    """Client for AI Forge's Universal Agent PEP Gateway and Ed25519 Evidence Plane."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        agent_id: str = "agent_security_pr_auditor",
        timeout_seconds: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.agent_id = agent_id
        self.timeout_seconds = timeout_seconds
        self.session_decisions: List[Dict[str, Any]] = []
        self.session_tool_calls: List[Dict[str, Any]] = []

    def _post_json(self, path: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        req = urllib.request.Request(
            url=f"{self.base_url}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
                "User-Agent": "AiForgePythonSDK/0.2.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as err:
            raw = err.read().decode("utf-8", errors="replace")
            try:
                return json.loads(raw)
            except Exception as exc:
                raise RuntimeError(f"AI Forge Gateway HTTP {err.code}: {raw}") from exc

    def authorize_tool_call(
        self,
        *,
        capability: str,
        action: str,
        effect: Literal["read", "write"],
        resource: str,
        data_classification: Literal["public", "internal", "confidential", "restricted"] = "internal",
        purpose: Optional[str] = None,
        run_id: Optional[str] = None,
        current_cost_usd: float = 0.0,
    ) -> Dict[str, Any]:
        data = self._post_json(
            "/api/v1/gateway/authorize",
            {
                "externalAgentId": self.agent_id,
                "externalRunId": run_id,
                "capability": capability,
                "action": action,
                "effect": effect,
                "resource": resource,
                "dataClassification": data_classification,
                "purpose": purpose or f"Python SDK governed call: {capability}/{action}",
                "currentCostUsd": current_cost_usd,
                "currentToolCalls": len(self.session_tool_calls),
            },
        )
        decision = data.get("decision", "deny")
        reason_code = data.get("reasonCode", "gateway_error")
        self.session_decisions.append(
            {
                "action": action,
                "resource": resource,
                "decision": decision,
                "reasonCode": reason_code,
            }
        )
        return data

    def governed_tool(
        self,
        *,
        capability: str,
        action: str,
        effect: Literal["read", "write"],
        resource_arg: str = "resource",
        default_resource: str = "org-approved/payments-api",
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator that enforces AI Forge PEP authorization before executing a Python tool."""

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                resource = str(kwargs.get(resource_arg, default_resource))
                started = time.monotonic()
                auth = self.authorize_tool_call(
                    capability=capability,
                    action=action,
                    effect=effect,
                    resource=resource,
                )
                decision = auth.get("decision")
                if decision != "allow" or not auth.get("delegatedCredential"):
                    self.session_tool_calls.append(
                        {
                            "capability": capability,
                            "action": action,
                            "status": "blocked",
                            "latencyMs": max(1, int((time.monotonic() - started) * 1000)),
                            "costUsd": 0.0,
                        }
                    )
                    raise AiForgePolicyDeniedError(
                        decision=str(decision),
                        reason_code=str(auth.get("reasonCode", "denied")),
                        resource=resource,
                        explanation=str(auth.get("explanation", "")),
                    )
                try:
                    result = func(*args, **kwargs)
                    self.session_tool_calls.append(
                        {
                            "capability": capability,
                            "action": action,
                            "status": "succeeded",
                            "latencyMs": max(1, int((time.monotonic() - started) * 1000)),
                            "costUsd": 0.0,
                        }
                    )
                    return result
                except Exception:
                    self.session_tool_calls.append(
                        {
                            "capability": capability,
                            "action": action,
                            "status": "failed",
                            "latencyMs": max(1, int((time.monotonic() - started) * 1000)),
                            "costUsd": 0.0,
                        }
                    )
                    raise

            return wrapper

        return decorator

    def submit_evidence(
        self,
        *,
        status: Literal["succeeded", "failed", "blocked"] = "succeeded",
        input_payload: Optional[Dict[str, Any]] = None,
        output_payload: Optional[Dict[str, Any]] = None,
        cost_usd: float = 0.0,
        input_tokens: int = 0,
        output_tokens: int = 0,
    ) -> Dict[str, Any]:
        """Seals the governed execution run and returns an Ed25519 + SHA-256 signed EvidenceBundle."""
        return self._post_json(
            "/api/v1/gateway/evidence",
            {
                "externalAgentId": self.agent_id,
                "status": status,
                "inputPayload": input_payload or {},
                "outputPayload": output_payload or {},
                "cost": {
                    "totalUsd": cost_usd,
                    "inputTokens": input_tokens,
                    "outputTokens": output_tokens,
                },
                "policyDecisions": self.session_decisions,
                "toolCalls": self.session_tool_calls,
            },
        )

