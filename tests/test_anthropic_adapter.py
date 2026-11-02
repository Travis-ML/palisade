# tests/test_anthropic_adapter.py
from types import SimpleNamespace

import pytest

from palisade.adapters.anthropic_client import UnknownToolError, proposed_actions_from_blocks
from palisade.core.types import ActionClass, ActionDomain, BlastRadius, Reversibility

CATALOG = {
    "ti_lookup_indicator": ActionClass(domain=ActionDomain.ENRICH,
                                       reversibility=Reversibility.REVERSIBLE,
                                       blast_radius=BlastRadius.SINGLE),
}


def block(name, **inputs):
    return SimpleNamespace(type="tool_use", id="toolu_01", name=name, input=inputs)


def test_known_tool_becomes_classified_action():
    actions = proposed_actions_from_blocks([block("ti_lookup_indicator", indicator="203.0.113.57",
                                                  indicator_type="ipv4")], CATALOG)
    assert len(actions) == 1
    assert actions[0].action_class.key() == "enrich:reversible:single"
    assert actions[0].target_ids == ["203.0.113.57"]
    assert actions[0].action_id == "toolu_01"


def test_unknown_tool_is_refused_not_guessed():
    with pytest.raises(UnknownToolError):
        proposed_actions_from_blocks([block("fw_block_cidr", cidr="10.0.0.0/8")], CATALOG)
