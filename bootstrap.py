# palisade/bootstrap.py  (the wiring order; `lab` is the LabEnvironment of Appendix I.8)
from palisade.settings import load_settings, bind_plane
from palisade.ledger.ledger import Ledger
from palisade.roe import RoEStore
from palisade.identity.broker import CredentialBroker
from palisade.policy.engine import PolicyEngine
from palisade.gateway import Gateway
from palisade.hitl.gate import ApprovalGate
from palisade.hitl.killswitch import KillSwitch
from palisade.router import ModelRouter, RoutingPolicy, TaskDescriptor
from palisade.loop import ContextAssembler, GovernedLoop
from palisade.core.types import AutonomyTier


def build_loop(task: TaskDescriptor, tier: AutonomyTier, *, operating_prompt: str, lab) -> GovernedLoop:
    """`lab` supplies the collaborators a chapter leaves to the environment: the approver
    channel, the tool transport, the identity registry, the signing keys, the tier registry,
    and the target resolver. The lab kit (Appendix I.8) provides lab versions of each."""
    settings = load_settings()
    bound = bind_plane(settings)                                   # raises; nothing below runs unbound
    ledger = Ledger.open(settings.roe_dir.parent / "ledger")      # Chapter 10
    roe_store = RoEStore(keys=lab.key_registry, plane=bound.plane)  # Chapter 11
    broker = CredentialBroker(lab.identity_registry, lab.broker_key, lab.broker_key_id)  # Chapter 12
    policy = PolicyEngine(base_url=settings.endpoints.opa_url)    # Chapter 14; fails closed
    gateway = Gateway(lab.tool_registry, policy, roe_store, broker, lab.tiers, lab.resolver,
                      lab.transport, sink=ledger, identities={bound.agent.agent_id: bound.agent})  # Chapter 7
    gate = ApprovalGate(lab.presenter, lab.scorer, lab.escalation, lab.channel,
                        roe_lookup=roe_store.active, reversal_paths=lab.reversal_paths)  # Chapter 13
    kill = KillSwitch(lab.runs, broker, ledger, lab.trip_state)   # Chapter 13
    router = ModelRouter(RoutingPolicy.from_yaml(lab.routing_policy_path, lab.settings_map), lab.clients,
                         bound_plane=bound.plane, roe_store=roe_store)  # Chapter 6
    return GovernedLoop(agent=bound.agent, task=task, tier=tier, router=router,
                        assembler=ContextAssembler(operating_prompt), gateway=gateway,
                        approval_gate=gate, broker=broker, ledger=ledger, kill_switch=kill,
                        tools=lab.tool_registry.definitions_for(bound.tools))
