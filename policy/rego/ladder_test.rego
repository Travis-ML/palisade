# palisade/policy/rego/ladder_test.rego
package palisade.authz_test

import rego.v1

import data.palisade.authz

# `base` is the baseline input from authz_test.rego (same package).
test_ladder_ceiling_denies_a_corrupted_registry if {
	d := authz.decision with input as base
		with data.ladder as {"ceilings": {"production_control:semi_reversible:single": 3}}
	d.verdict == "deny"
	"ladder.above_ceiling" in d.reasons
}

test_ladder_ceiling_at_or_above_the_tier_allows if {
	d := authz.decision with input as base
		with data.ladder as {"ceilings": {"production_control:semi_reversible:single": 4}}
	d.verdict == "allow"
}
