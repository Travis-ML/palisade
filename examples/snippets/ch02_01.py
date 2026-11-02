from typing import Literal

from pydantic import BaseModel, Field, model_validator


class VerdictOutput(BaseModel):
    label: Literal["benign", "suspicious", "malicious"]
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(min_length=1, description="Citations to retrieved items or query results")

    @model_validator(mode="after")
    def confidence_requires_evidence(self) -> "VerdictOutput":
        if self.confidence > 0.8 and len(self.evidence) < 2:
            raise ValueError("high confidence requires at least two cited pieces of evidence")
        return self


def parse_verdict(tool_input: dict) -> VerdictOutput:
    return VerdictOutput.model_validate(tool_input)   # raises on malformed or implausible output
