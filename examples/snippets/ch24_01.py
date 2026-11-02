# How the scenario engine wires the stop control between phases.
from palisade.hitl.killswitch import KillSwitch     # Chapter 13


def run_phase(engine, phase, roe, approvals) -> None:
    if engine.stop_requested():                      # checked before every phase
        KillSwitch().trip(scope=engine.engagement_id, by="stop_authority",
                          reason="operator stop between phases")
        engine.revoke_range_credentials()            # halt is not enough; revoke too
        return
    if phase.high_impact and phase.phase_index > 0:
        # Checkpoint between kill-chain phases: a human must continue a high-impact run.
        if not approvals.phase_continue_granted(engine.engagement_id, phase.phase_index):
            engine.pause(reason="awaiting between-phase human checkpoint")
            return
    engine.execute_phase(phase)                      # only objectives + technique IDs; Section 24.8
