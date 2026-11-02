"""palisade/adapters/runtime_hook.py: insert the governed step into an adopted runtime."""
from palisade.core.types import ActionClass, AgentIdentity, GlassBoxVerdict, ProposedAction, RunState
from palisade.gateway import Gateway
from palisade.hitl.gate import ApprovalGate


class GovernedToolHook:
    """Register as the runtime's tool executor. The runtime proposes; Palisade disposes."""

    def __init__(self, gateway: Gateway, gate: ApprovalGate, classify: dict[str, ActionClass]) -> None:
        self.gateway, self.gate, self.classify = gateway, gate, classify

    def __call__(self, tool_name: str, arguments: dict, agent: AgentIdentity, state: RunState,
                 glass_box: GlassBoxVerdict) -> dict:
        if tool_name not in self.classify:
            raise PermissionError(f"{tool_name} not in the action taxonomy (default deny)")
        action = ProposedAction(tool_name=tool_name, arguments=arguments, action_class=self.classify[tool_name])
        decision = self.gateway.authorize(action, agent, state)
        if decision.verdict == "deny":
            raise PermissionError(f"denied by {decision.rule_id}")
        approval = self.gate.request(action, glass_box, decision) if decision.verdict == "escalate" else None
        if approval is not None and approval.decision == "denied":
            raise PermissionError("approver denied the action")
        record = self.gateway.execute(action, decision, approval=approval)
        return {"status": record.status, "summary": record.result_summary}
