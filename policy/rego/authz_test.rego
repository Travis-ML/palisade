# palisade/policy/rego/authz_test.rego
package palisade.authz_test

import rego.v1

import data.palisade.authz

base := {
	"action": {
		"tool_name": "edr_isolate_host",
		"action_class": {"domain": "production_control", "reversibility": "semi_reversible", "blast_radius": "single"},
		"targets": [{"id": "host-4471", "labels": ["host:host-4471", "group:workstations", "tenant:tenant-acme"]}],
		"arguments": {"host_id": "host-4471", "ttl_minutes": 240},
	},
	"agent": {"agent_id": "spiffe://palisade.example/agent/response", "plane": "defensive", "effective_tier": 4},
	"roe": {
		"engagement_id": "eng_2026q4_soc_triage", "plane": "defensive", "active": true,
		"not_before_epoch": 1760000000, "not_after_epoch": 1767000000,
		"scope": {
			"in_scope": ["group:workstations", "tenant:tenant-acme"],
			"out_of_scope": ["group:domain_controllers", "host:host-dc01"],
		},
		"ceilings": [{
			"action_class": {"domain": "production_control", "reversibility": "semi_reversible", "blast_radius": "single"},
			"max_tier": 4, "rate_limit": "1/10m",
		}],
	},
	"state": {"engagement_id": "eng_2026q4_soc_triage", "now_epoch": 1760500000, "recent_actions": [], "flagged_context": false},
}

# An irreversible class that exists in the generated data: a message to one user cannot be recalled.
notify_class := {"domain": "internal_change", "reversibility": "irreversible", "blast_radius": "single"}

irreversible := [
	{"op": "replace", "path": "/action/tool_name", "value": "notify_user"},
	{"op": "replace", "path": "/action/action_class", "value": notify_class},
	{"op": "replace", "path": "/roe/ceilings/0/action_class", "value": notify_class},
]

test_allow_in_scope_within_ceiling if {
	d := authz.decision with input as base
	d.verdict == "allow"
	d.rule_id == "allow.within_ceiling"
}

test_default_deny_on_empty_input if {
	d := authz.decision with input as {}
	d.verdict == "deny"
}

test_explicit_deny_wins_over_in_scope if {
	# A domain controller that is ALSO tagged as a workstation: the deny label wins.
	patched := json.patch(base, [{"op": "replace", "path": "/action/targets/0/labels", "value": ["host:host-dc01", "group:workstations"]}])
	d := authz.decision with input as patched
	d.verdict == "deny"
	"roe.scope.explicit_deny" in d.reasons
}

test_deny_plane_tool_binding if {
	patched := json.patch(base, [
		{"op": "replace", "path": "/action/tool_name", "value": "range_emulate_step"},
		{"op": "replace", "path": "/action/action_class", "value": {"domain": "offense", "reversibility": "irreversible", "blast_radius": "group"}},
	])
	d := authz.decision with input as patched
	d.verdict == "deny"
	"plane.tool_binding" in d.reasons
}

test_roe_ceiling_caps_agent_tier if {
	# Agent claims tier 5; RoE grants at most 3 for the class: capped, so escalate.
	d := authz.decision with input as json.patch(base, [
		{"op": "replace", "path": "/agent/effective_tier", "value": 5},
		{"op": "replace", "path": "/roe/ceilings/0/max_tier", "value": 3},
	])
	d.verdict == "escalate"
	d.effective_tier == 3
}

test_deny_tier_too_low_for_human_to_lift if {
	d := authz.decision with input as json.patch(base, [{"op": "replace", "path": "/agent/effective_tier", "value": 2}])
	d.verdict == "deny"
	"ceiling.tier_too_low" in d.reasons
}

test_irreversible_without_intent_is_denied if {
	patched := json.patch(base, irreversible)
	d := authz.decision with input as patched
	d.verdict == "deny"
	"intent.required" in d.reasons
}

test_rate_limit_second_action_in_window_escalates if {
	patched := json.patch(base, [{"op": "replace", "path": "/state/recent_actions", "value": [
		{"class_key": "production_control:semi_reversible:single", "at_epoch": 1760499700},
	]}])
	d := authz.decision with input as patched
	d.verdict == "escalate"
	d.rule_id == "rate.limit_exceeded"
	d.evaluated_inputs.recent_in_window == 1
}

test_rate_limit_old_action_outside_window_is_ignored if {
	# 1000 seconds ago is outside the 10 minute window, so it does not count.
	patched := json.patch(base, [{"op": "replace", "path": "/state/recent_actions", "value": [
		{"class_key": "production_control:semi_reversible:single", "at_epoch": 1760499000},
	]}])
	d := authz.decision with input as patched
	d.verdict == "allow"
	d.evaluated_inputs.recent_in_window == 0
}

test_deny_roe_inactive if {
	d := authz.decision with input as json.patch(base, [{"op": "replace", "path": "/roe/active", "value": false}])
	d.verdict == "deny"
	"roe.inactive" in d.reasons
}

test_deny_outside_roe_window if {
	d := authz.decision with input as json.patch(base, [{"op": "replace", "path": "/state/now_epoch", "value": 1770000000}])
	d.verdict == "deny"
	"roe.window" in d.reasons
}

test_deny_target_not_in_scope if {
	d := authz.decision with input as json.patch(base, [
		{"op": "replace", "path": "/action/targets/0/labels", "value": ["host:host-9001", "group:servers"]},
	])
	d.verdict == "deny"
	"roe.scope.not_in_scope" in d.reasons
}

test_deny_unknown_tool if {
	d := authz.decision with input as json.patch(base, [{"op": "replace", "path": "/action/tool_name", "value": "mystery_tool"}])
	d.verdict == "deny"
	"tool.unknown" in d.reasons
}

test_deny_missing_ceiling if {
	d := authz.decision with input as json.patch(base, [{"op": "replace", "path": "/roe/ceilings", "value": []}])
	d.verdict == "deny"
	"roe.ceiling.missing" in d.reasons
}

test_tier_3_escalates_to_a_human if {
	# Tier 3 is below the tier 4 the class needs, but a human can lift it: escalate, not deny.
	d := authz.decision with input as json.patch(base, [{"op": "replace", "path": "/agent/effective_tier", "value": 3}])
	d.verdict == "escalate"
	d.rule_id == "ceiling.tier_insufficient"
}

test_observe_allowed_at_tier_0 if {
	observe := {"domain": "observe", "reversibility": "reversible", "blast_radius": "single"}
	d := authz.decision with input as json.patch(base, [
		{"op": "replace", "path": "/action/tool_name", "value": "siem_query"},
		{"op": "replace", "path": "/action/action_class", "value": observe},
		{"op": "replace", "path": "/agent/effective_tier", "value": 0},
		{"op": "replace", "path": "/roe/ceilings/0", "value": {"action_class": observe, "max_tier": 0}},
	])
	d.verdict == "allow"
}

test_shadow_agent_cannot_escalate_an_irreversible_action if {
	# Tier 0 means shadow: nothing in production control, not even with a human in the path.
	intent := {
		"intent": "contain", "necessity": "active spread", "harm": "user locked out",
		"data": "none leaves the account", "alternatives": "session revoke was not enough",
	}
	patched := json.patch(base, array.concat(irreversible, [
		{"op": "add", "path": "/action/intent", "value": intent},
		{"op": "replace", "path": "/agent/effective_tier", "value": 0},
	]))
	d := authz.decision with input as patched
	d.verdict == "deny"
	"ceiling.tier_too_low" in d.reasons
}

test_irreversible_with_intent_still_escalates if {
	intent := {
		"intent": "contain", "necessity": "active spread", "harm": "user locked out",
		"data": "none leaves the account", "alternatives": "session revoke was not enough",
	}
	patched := json.patch(base, array.concat(irreversible, [{"op": "add", "path": "/action/intent", "value": intent}]))
	d := authz.decision with input as patched
	d.verdict == "escalate"
	d.rule_id == "ceiling.tier_insufficient"
}

test_five_question_class_always_escalates if {
	# No class in today's catalog carries approval_always (a tool such as idp_reset_credential would add one),
	# so the test supplies it: the class needs tier 3, the agent holds 4, and a human is still required.
	taxonomy := {"production_control:semi_reversible:single": {"required_tier": 3, "approval_always": true}}
	intent := {
		"intent": "contain", "necessity": "active spread", "harm": "user locked out",
		"data": "none leaves the account", "alternatives": "session revoke was not enough",
	}
	with_intent := authz.decision with input as json.patch(base, [{"op": "add", "path": "/action/intent", "value": intent}])
		with data.palisade.taxonomy as taxonomy
	with_intent.verdict == "escalate"
	with_intent.rule_id == "ceiling.approval_required"
	without_intent := authz.decision with input as base with data.palisade.taxonomy as taxonomy
	without_intent.verdict == "deny"
	"intent.required" in without_intent.reasons
}

test_null_intent_counts_as_missing if {
	# A caller that serializes "no intent" as null must not slip past the intent rule.
	patched := json.patch(base, array.concat(irreversible, [{"op": "add", "path": "/action/intent", "value": null}]))
	d := authz.decision with input as patched
	d.verdict == "deny"
	"intent.required" in d.reasons
}

test_missing_out_of_scope_is_malformed_not_open if {
	# A document that omits the deny list must not admit a target the RoE would have excluded.
	patched := json.patch(base, [
		{"op": "replace", "path": "/action/targets/0/labels", "value": ["host:host-dc01", "group:workstations"]},
		{"op": "remove", "path": "/roe/scope/out_of_scope"},
	])
	d := authz.decision with input as patched
	d.verdict == "deny"
	"input.malformed" in d.reasons
}

test_missing_clock_is_malformed if {
	# Without now_epoch the window rules are undefined, not violated; completeness catches it.
	d := authz.decision with input as json.patch(base, [{"op": "remove", "path": "/state/now_epoch"}])
	d.verdict == "deny"
	"input.malformed" in d.reasons
}

test_no_roe_is_inactive_not_malformed if {
	# With no RoE the gateway sends only {"active": false}; the refusal names the real cause.
	d := authz.decision with input as json.patch(base, [{"op": "replace", "path": "/roe", "value": {"active": false}}])
	d.verdict == "deny"
	"roe.inactive" in d.reasons
	not "input.malformed" in d.reasons
}

test_irreversible_with_reversible_sibling_escalates if {
	# A tier-5 agent under a tier-5 ceiling would be allowed; the sibling makes it a human decision.
	# No tool in today's catalog is both irreversible and has a sibling, so the test supplies the name.
	intent := {
		"intent": "notify", "necessity": "user must act", "harm": "none recallable",
		"data": "no sensitive data", "alternatives": "a draft for review was not enough",
	}
	allowed := json.patch(base, array.concat(irreversible, [
		{"op": "add", "path": "/action/intent", "value": intent},
		{"op": "replace", "path": "/agent/effective_tier", "value": 5},
		{"op": "replace", "path": "/roe/ceilings/0/max_tier", "value": 5},
	]))
	before := authz.decision with input as allowed
	before.verdict == "allow"
	d := authz.decision with input as json.patch(allowed, [{"op": "add", "path": "/action/reversible_alternative", "value": "notify_user_draft"}])
	d.verdict == "escalate"
	d.rule_id == "reversible.alternative_available"
	d.evaluated_inputs.reversible_alternative == "notify_user_draft"
}

test_flagged_context_escalates_a_state_changing_action if {
	# An injection that reached the context is converted from an executed action into an approval request.
	d := authz.decision with input as json.patch(base, [{"op": "replace", "path": "/state/flagged_context", "value": true}])
	d.verdict == "escalate"
	d.rule_id == "context.flagged"
}

test_flagged_context_does_not_block_reading if {
	# The agent still has to analyze the hostile content; observing is allowed.
	observe := {"domain": "observe", "reversibility": "reversible", "blast_radius": "single"}
	d := authz.decision with input as json.patch(base, [
		{"op": "replace", "path": "/action/tool_name", "value": "siem_query"},
		{"op": "replace", "path": "/action/action_class", "value": observe},
		{"op": "replace", "path": "/roe/ceilings/0", "value": {"action_class": observe, "max_tier": 4}},
		{"op": "replace", "path": "/state/flagged_context", "value": true},
	])
	d.verdict == "allow"
}
