# palisade/settings.py  (built in Chapter 4, Section 4.5; shape only)
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional

from pydantic import BaseModel, Field

from palisade.core.types import Plane
from palisade.tools.catalog import TOOL_CATALOG


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

def load_settings(path: str | os.PathLike | None = None) -> Settings: ...   # PALISADE_CONFIG or config/palisade.yaml
class BoundPlane(BaseModel): ...                                              # plane, agent, tools, bound_at (Chapter 4)

def bind_plane(settings: Settings, catalog=TOOL_CATALOG) -> BoundPlane: ...  # raises PlaneBindingError
