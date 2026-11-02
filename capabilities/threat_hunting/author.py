# palisade/capabilities/threat_hunting/author.py
from __future__ import annotations

from palisade.core.types import (
    ActionClass, ActionDomain, AgentIdentity, BlastRadius, DecisionRecord,
    ModelCallRecord, ProposedAction, Reversibility, RunState,
)
from palisade.gateway import Gateway
from palisade.ledger.ledger import Ledger
from palisade.loop import ContextAssembler
from palisade.router import ModelRouter, TaskDescriptor

OBSERVE = ActionClass(domain=ActionDomain.OBSERVE, reversibility=Reversibility.REVERSIBLE,
                      blast_radius=BlastRadius.SINGLE)
DRAFT_RULE = ActionClass(domain=ActionDomain.INTERNAL_CHANGE,
                         reversibility=Reversibility.SEMI_REVERSIBLE, blast_radius=BlastRadius.SINGLE)

THRESHOLDS = {"precision": 0.80, "recall": 0.90, "max_match_rate": 0.001}


class DetectionAuthoringLoop:
    """Generate a Sigma rule, test it against the labeled corpus, refine, end in a PR."""

    def __init__(self, gateway: Gateway, ledger: Ledger, router: ModelRouter,
                 assembler: ContextAssembler, agent: AgentIdentity, max_iterations: int = 5):
        self.gw, self.ledger, self.router, self.assembler = gateway, ledger, router, assembler
        self.agent, self.max_iterations = agent, max_iterations

    def _step(self, state: RunState, action: ProposedAction, context_hash: str,
              model_call: ModelCallRecord | None = None) -> dict:
        decision = self.gw.authorize(action, self.agent, state)
        execution = self.gw.execute(action, decision) if decision.verdict == "allow" else None
        rec = DecisionRecord(run_id=state.run_id, step=state.step, agent_id=self.agent.agent_id,
                             plane=self.agent.plane, engagement_id=state.engagement_id,
                             autonomy_tier=decision.effective_tier, context_hash=context_hash,
                             model_call=model_call, proposed_action=action,
                             policy_decision=decision, execution=execution)
        state.last_record_hash = self.ledger.append(rec.seal(state.last_record_hash))
        state.step += 1
        if decision.verdict != "allow":
            state.halted, state.halt_reason = True, f"{decision.verdict}:{decision.rule_id}"
            raise RuntimeError(state.halt_reason)
        return _parse(execution.result_summary)

    def run(self, state: RunState, hunt_summary: dict, corpus_id: str, repo: str) -> dict | None:
        feedback: list[str] = []
        for i in range(self.max_iterations):
            ctx = self.assembler.assemble(state, _retrieve_sigma_guidance() + [_untrusted(hunt_summary, feedback)])
            rd = self.router.select(TaskDescriptor(capability="threat_hunting", kind="detection_author",
                                                   sensitivity="internal"))
            turn = rd.client.complete(ctx.messages, tools=[])
            rule_yaml = _extract_sigma(turn.text)                     # schema-validated Sigma
            mc = ModelCallRecord(model_id=rd.model_id, model_version=rd.model_version,
                                 routing_rule=rd.rule_id, input_tokens=turn.usage.input_tokens,
                                 output_tokens=turn.usage.output_tokens)
            report = self._step(state, ProposedAction(
                tool_name="detection_test", arguments={"rule_yaml": rule_yaml, "corpus_id": corpus_id},
                action_class=OBSERVE, target_ids=[corpus_id],
                rationale=f"iteration {i + 1}: test candidate against labeled corpus"),
                context_hash=ctx.hash, model_call=mc)
            verdict = self._evaluate(report)
            if verdict["accepted"]:
                return self._step(state, ProposedAction(
                    tool_name="scm_open_pr",
                    arguments={"repo": repo, "branch": f"palisade/detection/{state.run_id}",
                               "title": f"detect: {report['title']}",
                               "body": _pr_body(hunt_summary, report, state), "reviewers": ["detection-eng"]},
                    action_class=DRAFT_RULE, target_ids=[repo],
                    rationale="critic satisfied; open PR for detection engineering review"),
                    context_hash=ctx.hash)
            feedback = verdict["failures"]
        return None

    @staticmethod
    def _evaluate(r: dict) -> dict:
        failures: list[str] = []
        if r["precision"] < THRESHOLDS["precision"]:
            failures.append(f"precision {r['precision']:.2f} < {THRESHOLDS['precision']}; "
                            f"top false positives: {r['fp_examples'][:3]}")
        if r["recall"] < THRESHOLDS["recall"]:
            failures.append(f"recall {r['recall']:.2f}; missed: {r['fn_examples'][:3]}")
        if r["match_rate"] > THRESHOLDS["max_match_rate"]:
            failures.append(f"over-broad: matches {r['match_rate']:.2%} of corpus")
        return {"accepted": not failures, "failures": failures}
