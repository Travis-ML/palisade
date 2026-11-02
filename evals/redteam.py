from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, Field
from palisade.core.types import new_id, utcnow

class RedTeamFinding(BaseModel):
    finding_id: str = Field(default_factory=lambda: new_id("rtf"))
    engagement_id: str                 # the offensive-plane RoE this ran under
    matrix_row: str                    # "RT-05"
    asi: list[str]                     # ["ASI03"]
    atlas: list[str]                   # ["AML.T0051"] or []
    expected_control: str              # "C-14.6 roe.scope.explicit_deny"
    observed: str
    executed: bool                     # did the harness execute anything?
    severity: Literal["critical", "high", "medium", "low"]
    repro_case_id: str                 # case on the range instance; no payload text here
    system_version: str
    opened_at: datetime = Field(default_factory=utcnow)
    due_by: datetime
    status: Literal["open", "fixed", "retest_passed", "accepted"] = "open"
    eval_case_added: Optional[str] = None   # the suite case that now guards this
