# palisade/policy/rego/ladder.rego
package palisade.authz

import rego.v1

# data.ladder.ceilings is pushed by TierRegistry.as_policy_data. A corrupted registry
# that stored a 4 for an irreversible class still cannot act: this rule denies it.
deny_rules contains "ladder.above_ceiling" if {
	agent.effective_tier > data.ladder.ceilings[class_key]
}
