# tests/test_plane_binding.py
import pytest

from palisade.core.types import Plane
from palisade.settings import (AgentConfig, EndpointsConfig, ModelsConfig, PlaneBindingError,
                               Settings, bind_plane)

ENDPOINTS = dict(opa_url="http://opa", ledger_url="http://ledger", broker_url="http://broker",
                 killswitch_url="http://ks", otel_endpoint="http://ledger")
AGENT = AgentConfig(agent_id="spiffe://palisade.example/agent/triage", display_name="triage",
                    owner="soc-lead@palisade.example")


def settings_for(plane: Plane, tools: list[str], models: ModelsConfig) -> Settings:
    return Settings(plane=plane, agent=AGENT, models=models,
                    endpoints=EndpointsConfig(mcp_servers={t: f"http://{t}" for t in tools}, **ENDPOINTS))


def test_defensive_binding_succeeds(monkeypatch):
    monkeypatch.setenv("PALISADE_PLANE", "defensive")
    bound = bind_plane(settings_for(Plane.DEFENSIVE, ["siem_query", "edr_get_host"],
                                    ModelsConfig(frontier="cfg-frontier")))
    assert bound.plane is Plane.DEFENSIVE and bound.tools == ("edr_get_host", "siem_query")


def test_offensive_plane_refuses_a_production_tool(monkeypatch):
    monkeypatch.setenv("PALISADE_PLANE", "offensive")
    with pytest.raises(PlaneBindingError, match="edr_isolate_host"):
        bind_plane(settings_for(Plane.OFFENSIVE, ["range_emulate_step", "edr_isolate_host"],
                                ModelsConfig(contained="cfg-contained", api_base="http://vllm:8000/v1")))


def test_deployment_and_config_must_agree(monkeypatch):
    monkeypatch.setenv("PALISADE_PLANE", "offensive")
    with pytest.raises(PlaneBindingError, match="deployment declares"):
        bind_plane(settings_for(Plane.DEFENSIVE, ["siem_query"], ModelsConfig(frontier="cfg-frontier")))


def test_defensive_plane_refuses_a_contained_model(monkeypatch):
    monkeypatch.setenv("PALISADE_PLANE", "defensive")
    with pytest.raises(PlaneBindingError, match="A19"):
        bind_plane(settings_for(Plane.DEFENSIVE, ["siem_query"],
                                ModelsConfig(frontier="cfg-frontier", contained="cfg-contained")))
