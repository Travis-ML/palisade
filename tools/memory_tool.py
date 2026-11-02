# palisade/tools/memory_tool.py: the registry entry for the governed memory write
from palisade.core.types import ActionClass, ActionDomain, AutonomyTier, BlastRadius, Plane, Reversibility
from palisade.tools.spec import ToolSpec

MEMORY_WRITE = ToolSpec(
    name="memory_write", server="palisade-memory", server_version="1.0.0",
    description=("Persist ONE conclusion for future runs, with evidence references. Semi-reversible "
                 "(rollback by new version), single object. Conclusions only: no transcripts, no "
                 "instructions, no secrets. The stored trust tier is the lowest tier of the evidence."),
    input_schema={
        "type": "object",
        "properties": {
            "tenant": {"type": "string", "pattern": "^tenant-[a-z0-9]+$"},
            "key": {"type": "string", "pattern": "^(host|user|indicator|baseline|case|verdict)/[A-Za-z0-9_./-]{1,120}$"},
            "value": {"type": "object"},
            "evidence": {"type": "array", "minItems": 1, "maxItems": 20, "items": {"type": "string"}},
            "evidence_tiers": {"type": "array", "items": {"enum": ["enterprise", "verified", "untrusted"]}},
            "reason": {"type": "string", "minLength": 10, "maxLength": 300},
        },
        "required": ["tenant", "key", "value", "evidence", "evidence_tiers", "reason"],
        "additionalProperties": False,
    },
    plane=Plane.DEFENSIVE,
    action_class=ActionClass(domain=ActionDomain.INTERNAL_CHANGE,
                             reversibility=Reversibility.SEMI_REVERSIBLE, blast_radius=BlastRadius.SINGLE),
    required_tier=AutonomyTier.ACT_WITHIN_SCOPE,
    permissions=["memory:write"],
    resource_template="memory:{tenant}:{key}",
)
