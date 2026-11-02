from pydantic import BaseModel, ConfigDict, Field
from typing import Literal

class EdrIsolateHostArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    host_id: str = Field(pattern=r"^host-\d{4}$")
    ttl_minutes: int = Field(ge=15, le=1440)
    reason: str = Field(min_length=20, max_length=500)

class NotifyUserArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")
    user_id: str = Field(pattern=r"^u\.[a-z0-9.]{2,32}$")
    template: Literal["phish_confirmed", "phish_benign", "mfa_prompt_check"]   # no free-text body
    ticket_id: str = Field(pattern=r"^INC-\d{6,8}$")
