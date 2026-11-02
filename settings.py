"""
palisade/settings.py (Chapter 4)

Typed configuration and the plane binding performed once at startup. If binding fails,
the process exits before it has connected to a model, a tool server, or anything else.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field

from palisade.core.types import AgentIdentity, Plane, utcnow
from palisade.tools.catalog import TOOL_CATALOG, CatalogEntry


class ModelsConfig(BaseModel):
    frontier: Optional[str] = None    # managed API model id; defensive plane only
    fast: Optional[str] = None        # small model for classification and extraction
    contained: Optional[str] = None   # self-hosted open-weight model id; offensive plane only
    api_base: Optional[str] = None    # OpenAI-compatible base URL for self-hosted models (vLLM)


class EndpointsConfig(BaseModel):
    opa_url: str
    ledger_url: str
    broker_url: str
    killswitch_url: str
    otel_endpoint: str
    mcp_servers: dict[str, str] = Field(default_factory=dict)   # tool_name -> server URL


class AgentConfig(BaseModel):
    agent_id: str                      # spiffe://palisade.example/agent/<name>
    display_name: str
    owner: str                         # a named human, always
    recertify_days: int = 90


class Settings(BaseModel):
    plane: Plane
    agent: AgentConfig
    models: ModelsConfig
    endpoints: EndpointsConfig
    trust_domain: str = "palisade.example"
    roe_dir: Path = Path("roe")


def load_settings(path: str | os.PathLike | None = None) -> Settings:
    config_path = Path(path or os.environ.get("PALISADE_CONFIG", "config/palisade.yaml"))
    return Settings.model_validate(yaml.safe_load(config_path.read_text()))


class PlaneBindingError(RuntimeError):
    """Raised at startup when the process cannot prove which plane it is on. The process exits."""


class BoundPlane(BaseModel):
    model_config = ConfigDict(frozen=True)

    plane: Plane
    agent: AgentIdentity
    tools: tuple[str, ...]
    bound_at: datetime


def bind_plane(settings: Settings, catalog: dict[str, CatalogEntry] = TOOL_CATALOG) -> BoundPlane:
    declared = os.environ.get("PALISADE_PLANE")
    if declared is None:
        raise PlaneBindingError("PALISADE_PLANE is not set; the deployment must declare its plane")
    if declared != settings.plane.value:
        raise PlaneBindingError(f"config declares {settings.plane.value!r}; deployment declares {declared!r}")

    problems: list[str] = []
    for tool_name in settings.endpoints.mcp_servers:
        entry = catalog.get(tool_name)
        if entry is None:
            problems.append(f"{tool_name}: not in the tool catalog")
        elif entry.plane is not settings.plane:
            problems.append(f"{tool_name}: catalog binds it to the {entry.plane.value} plane")

    if settings.plane is Plane.OFFENSIVE:
        if settings.models.frontier is not None:
            problems.append("offensive plane may not configure a managed frontier model (no egress)")
        if settings.models.contained is None or settings.models.api_base is None:
            problems.append("offensive plane requires a contained model and an in-range api_base")
    else:
        if settings.models.contained is not None:
            problems.append("defensive plane may not configure a contained model (Control A19)")
        if settings.models.frontier is None:
            problems.append("defensive plane requires a frontier model")

    if problems:
        raise PlaneBindingError("; ".join(problems))

    agent = AgentIdentity(
        agent_id=settings.agent.agent_id,
        display_name=settings.agent.display_name,
        owner=settings.agent.owner,
        plane=settings.plane,
        recertify_by=utcnow() + timedelta(days=settings.agent.recertify_days),
    )
    return BoundPlane(plane=settings.plane, agent=agent,
                      tools=tuple(sorted(settings.endpoints.mcp_servers)), bound_at=utcnow())
