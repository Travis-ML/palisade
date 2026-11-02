# palisade/capabilities/vuln_remediation/remediate.py
from palisade.core.types import (
    ActionClass, ActionDomain, AgentIdentity, BlastRadius, DecisionRecord,
    ModelCallRecord, ProposedAction, Reversibility, RunState,
)
from palisade.gateway import Gateway
from palisade.ledger.ledger import Ledger
from palisade.loop import ContextAssembler
from palisade.router import ModelRouter, TaskDescriptor

INTERNAL_CHANGE = ActionClass(domain=ActionDomain.INTERNAL_CHANGE,
                              reversibility=Reversibility.SEMI_REVERSIBLE,
                              blast_radius=BlastRadius.SINGLE)
OBSERVE = ActionClass(domain=ActionDomain.OBSERVE, reversibility=Reversibility.REVERSIBLE,
                      blast_radius=BlastRadius.SINGLE)


class RemediationLoop:
    """Evaluator-optimizer workflow: the tool sequence is fixed in code, and each
    call is still a governed step through the gateway and the ledger."""

    def __init__(self, gateway: Gateway, ledger: Ledger, router: ModelRouter,
                 assembler: ContextAssembler, agent: AgentIdentity, max_iterations: int = 4):
        self.gw, self.ledger, self.router, self.assembler = gateway, ledger, router, assembler
        self.agent, self.max_iterations = agent, max_iterations

    def _step(self, state: RunState, action: ProposedAction, context_hash: str,
              model_call: ModelCallRecord | None = None) -> dict:
        """Authorize, execute, append. Halts on escalate or deny."""
        decision = self.gw.authorize(action, self.agent, state)
        execution = self.gw.execute(action, decision) if decision.verdict == "allow" else None
        record = DecisionRecord(
            run_id=state.run_id, step=state.step, agent_id=self.agent.agent_id,
            plane=self.agent.plane, engagement_id=state.engagement_id,
            autonomy_tier=decision.effective_tier, context_hash=context_hash,
            model_call=model_call, proposed_action=action,
            policy_decision=decision, execution=execution)
        state.last_record_hash = self.ledger.append(record.seal(state.last_record_hash))
        state.step += 1
        if decision.verdict != "allow":
            state.halted, state.halt_reason = True, f"{decision.verdict}:{decision.rule_id}"
            raise RuntimeError(state.halt_reason)
        return _parse(execution.result_summary)

    def run(self, state: RunState, finding: dict, repo: str, base: str,
            reviewers: list[str]) -> dict | None:
        br = self._step(state, ProposedAction(
            tool_name="scm_create_branch",
            arguments={"repo": repo, "base": base, "finding_id": finding["finding_id"]},
            action_class=INTERNAL_CHANGE, target_ids=[repo],
            rationale=f"remediation branch for {finding['finding_id']}"), context_hash="")
        feedback: list[str] = []
        for i in range(self.max_iterations):
            retrieved = _retrieve_fix_patterns(finding, repo)          # ENTERPRISE tier
            ctx = self.assembler.assemble(state, retrieved + [_untrusted(finding, feedback)])
            rd = self.router.select(TaskDescriptor(capability="vuln_remediation",
                                                   kind="code_fix", sensitivity="internal"))
            turn = rd.client.complete(ctx.messages, tools=[])
            diff, message = _extract_diff(turn.text)                    # schema-validated
            mc = ModelCallRecord(model_id=rd.model_id, model_version=rd.model_version,
                                 routing_rule=rd.rule_id,
                                 input_tokens=turn.usage.input_tokens,
                                 output_tokens=turn.usage.output_tokens)
            self._step(state, ProposedAction(
                tool_name="scm_commit_patch",
                arguments={"repo": repo, "branch": br["branch"],
                           "unified_diff": diff, "message": message},
                action_class=INTERNAL_CHANGE, target_ids=[repo],
                rationale=f"iteration {i + 1}: {message}"), context_hash=ctx.hash, model_call=mc)
            ci = self._step(state, ProposedAction(
                tool_name="scm_run_ci", arguments={"repo": repo, "branch": br["branch"]},
                action_class=OBSERVE, target_ids=[repo],
                rationale="evaluate fix: tests and rescan"), context_hash=ctx.hash)
            verdict = self._evaluate(ci, finding, diff)
            if verdict["accepted"]:
                return self._step(state, ProposedAction(
                    tool_name="scm_open_pr",
                    arguments={"repo": repo, "branch": br["branch"],
                               "title": f"fix({finding['finding_id']}): {message}",
                               "body": _pr_body(finding, verdict, ci, state),
                               "reviewers": reviewers},
                    action_class=INTERNAL_CHANGE, target_ids=[repo],
                    rationale="critic satisfied; open PR for human review"), context_hash=ctx.hash)
            feedback = verdict["failures"]
        return None  # budget exhausted: no PR, attempt fully recorded

    @staticmethod
    def _evaluate(ci: dict, finding: dict, diff: str) -> dict:
        failures: list[str] = []
        if ci["status"] != "passed":
            failures += [f"CI job failed: {j}" for j in ci.get("failing_jobs", [])]
        present = set(ci.get("rescan_finding_ids", []))
        if finding["finding_id"] in present:
            failures.append("rescan: original finding still present")
        if (present - {finding["finding_id"]}) - set(finding.get("baseline_finding_ids", [])):
            failures.append("rescan: fix introduced new findings")
        if _diff_lines(diff) > 400:
            failures.append("diff exceeds 400 changed lines; narrow the fix")
        return {"accepted": not failures, "failures": failures}
