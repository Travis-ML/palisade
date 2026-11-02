# run_first_loop.py
from palisade.bootstrap import build_loop
from palisade.core.types import AutonomyTier, RunBudget
from palisade.labs.common import LabEnvironment
from palisade.router import TaskDescriptor

lab = LabEnvironment.from_compose()           # fakes for approvals and tool transport; real OPA, real ledger
task = TaskDescriptor(task_type="triage.verdict", plane=lab.plane, agent_id=lab.agent_id,
                      sensitivity="internal", engagement_id="eng_2026q4_soc_triage")
loop = build_loop(task, AutonomyTier.SHADOW, operating_prompt=lab.operating_prompt, lab=lab)

state = loop.run(goal="Triage alert alt_0001 for host-4471 and produce a glass-box verdict.",
                 budget=RunBudget(max_steps=20, max_cost_usd=2.0))
print(state.halted, state.halt_reason, state.step, state.cost_usd)
assert loop.ledger.verify_chain()
