# palisade/policy/rego/authz.rego
package palisade.authz

import rego.v1

# --- 1. Default deny -------------------------------------------------------

default decision := {
	"verdict": "deny",
	"rule_id": "default.deny",
	"reasons": ["no rule evaluated this action"],
	"required_tier": 5,
	"effective_tier": 0,
	"evaluated_inputs": {},
}

decision := deny_decision if count(deny_rules) > 0

decision := escalate_decision if {
	count(deny_rules) == 0
	count(escalate_rules) > 0
}

decision := allow_decision if {
	count(deny_rules) == 0
	count(escalate_rules) == 0
}

# --- 1b. Completeness: a missing field must never read as "no objection" ----
# A rule whose body reads a field that is absent is undefined, not false, so
# without this check a document that omits the scope or the clock would pass
# every rule that depends on them.

required_always := [
	["agent", "plane"],
	["agent", "effective_tier"],
	["roe", "active"],
	["action", "tool_name"],
	["action", "action_class", "domain"],
	["action", "action_class", "reversibility"],
	["action", "action_class", "blast_radius"],
	["action", "targets"],
	["state", "now_epoch"],
	["state", "recent_actions"],
	["state", "flagged_context"],
]

# With no RoE the gateway sends only {"active": false}; the rest is required
# once there is an RoE to evaluate against.
required_when_active := [
	["roe", "plane"],
	["roe", "engagement_id"],
	["roe", "not_before_epoch"],
	["roe", "not_after_epoch"],
	["roe", "scope", "in_scope"],
	["roe", "scope", "out_of_scope"],
	["roe", "ceilings"],
	["state", "engagement_id"],
]

deny_rules contains "input.malformed" if {
	some path in required_always
	is_null(object.get(input, path, null))
}

deny_rules contains "input.malformed" if {
	input.roe.active == true
	some path in required_when_active
	is_null(object.get(input, path, null))
}

# --- 2. Shorthands ---------------------------------------------------------

action := input.action

agent := input.agent

roe := input.roe

class_key := sprintf("%s:%s:%s", [
	action.action_class.domain,
	action.action_class.reversibility,
	action.action_class.blast_radius,
])

taxonomy := data.palisade.taxonomy[class_key]

tool := data.palisade.tools[action.tool_name]

# The RoE ceiling granted for exactly this action class, if any.
ceiling := c if {
	some c in roe.ceilings
	c.action_class.domain == action.action_class.domain
	c.action_class.reversibility == action.action_class.reversibility
	c.action_class.blast_radius == action.action_class.blast_radius
}

# The tier the agent holds, capped by what the RoE grants for this class.
default effective_tier := 0

effective_tier := min([agent.effective_tier, ceiling.max_tier])

default required_tier := 5

required_tier := taxonomy.required_tier

# --- 3. Engagement active --------------------------------------------------

deny_rules contains "roe.inactive" if not roe.active

deny_rules contains "roe.window" if input.state.now_epoch < roe.not_before_epoch

deny_rules contains "roe.window" if input.state.now_epoch > roe.not_after_epoch

deny_rules contains "roe.engagement_mismatch" if roe.engagement_id != input.state.engagement_id

# --- 4. Plane binding ------------------------------------------------------

deny_rules contains "plane.agent_roe_mismatch" if agent.plane != roe.plane

deny_rules contains "tool.unknown" if not tool

deny_rules contains "plane.tool_binding" if tool.plane != agent.plane

# --- 5. RoE scope: explicit deny wins, then every target must be in scope -

deny_rules contains "roe.scope.explicit_deny" if {
	some t in action.targets
	some label in t.labels
	label in roe.scope.out_of_scope
}

deny_rules contains "roe.scope.not_in_scope" if {
	some t in action.targets
	not target_in_scope(t)
}

deny_rules contains "roe.scope.no_targets" if {
	tool.requires_targets
	count(action.targets) == 0
}

target_in_scope(t) if {
	some label in t.labels
	label in roe.scope.in_scope
}

# --- 6. Ceilings per action class -----------------------------------------

deny_rules contains "taxonomy.unknown_class" if not taxonomy

deny_rules contains "roe.ceiling.missing" if not ceiling

deny_rules contains "ceiling.tier_too_low" if {
	effective_tier < required_tier
	effective_tier < 3 # below ACT_WITH_APPROVAL a human cannot lift it, even for approval_always classes
}

deny_rules contains "intent.required" if {
	requires_intent
	not intent_present
}

# A missing key and an explicit null both count as "no intent". `not action.intent`
# would let null through, because null is a defined value in Rego.
intent_present if is_object(action.intent)

requires_intent if action.action_class.reversibility == "irreversible"

requires_intent if action.action_class.blast_radius == "enterprise"

requires_intent if taxonomy.approval_always

escalate_rules contains "ceiling.approval_required" if taxonomy.approval_always

# An irreversible action whose reversible sibling exists goes to a human with the
# sibling named (Chapter 11, Section 11.6.3). The gateway looks the sibling up;
# the policy only reads it.
escalate_rules contains "reversible.alternative_available" if {
	action.action_class.reversibility == "irreversible"
	is_string(action.reversible_alternative)
}

# Screened content in this step's context (Section 14.2.2): anything that changes state goes
# to a human who sees the flagged text, whatever tier the agent holds. Reading is not blocked,
# because analyzing the hostile content is the job.
escalate_rules contains "context.flagged" if {
	input.state.flagged_context == true
	not action.action_class.domain in {"observe", "enrich"}
}

escalate_rules contains "ceiling.tier_insufficient" if {
	not taxonomy.approval_always
	effective_tier < required_tier
	effective_tier >= 3
}

# --- 7. Rate limits: a second action inside the window forces human review -

escalate_rules contains "rate.limit_exceeded" if {
	is_string(ceiling.rate_limit)
	recent_count >= rate_max
}

rate_parts := split(ceiling.rate_limit, "/") if is_string(ceiling.rate_limit)

rate_max := to_number(rate_parts[0])

window_seconds := to_number(m[0][1]) * unit_seconds[m[0][2]] if {
	m := regex.find_all_string_submatch_n(`^(\d+)([smh])$`, rate_parts[1], 1)
}

unit_seconds := {"s": 1, "m": 60, "h": 3600}

default recent_count := 0

recent_count := count([a |
	some a in input.state.recent_actions
	a.class_key == class_key
	input.state.now_epoch - a.at_epoch <= window_seconds
])

# --- 8. Decision objects (shape matches palisade.core.types.PolicyDecision)

default ceiling_max_tier := null

ceiling_max_tier := ceiling.max_tier

# Empty when the input was too incomplete to describe; the malformed-input rule
# still produces a deny with a rule id rather than falling through to default.deny.
default evaluated := {}

evaluated := {
	"class_key": class_key,
	"engagement_id": roe.engagement_id,
	"targets": [t.id | some t in action.targets],
	"ceiling_max_tier": ceiling_max_tier,
	"recent_in_window": recent_count,
	"reversible_alternative": object.get(action, "reversible_alternative", null),
}

deny_decision := {
	"verdict": "deny",
	"rule_id": sort(deny_rules)[0],
	"reasons": sort(deny_rules),
	"required_tier": required_tier,
	"effective_tier": effective_tier,
	"evaluated_inputs": evaluated,
}

escalate_decision := {
	"verdict": "escalate",
	"rule_id": sort(escalate_rules)[0],
	"reasons": sort(escalate_rules),
	"required_tier": required_tier,
	"effective_tier": effective_tier,
	"evaluated_inputs": evaluated,
}

allow_decision := {
	"verdict": "allow",
	"rule_id": "allow.within_ceiling",
	"reasons": ["in scope, within ceiling, under rate limit"],
	"required_tier": required_tier,
	"effective_tier": effective_tier,
	"evaluated_inputs": evaluated,
}
