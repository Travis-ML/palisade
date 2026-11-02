def test_expired_roe_is_not_returned(store, expired_roe):
    store.load(expired_roe)
    assert store.active("eng_2026q4_soc_triage") is None

def test_explicit_deny_wins(roe):
    m = ScopeMatcher(roe)
    assert m.check_target("cidr:10.20.4.17").in_scope          # inside the /16
    assert not m.check_target("cidr:10.20.250.9").in_scope     # inside the carved-out /24
    assert m.check_target("cidr:10.20.250.9").reason == "explicit_deny"

def test_an_object_is_judged_by_all_its_identifiers(roe):
    m = ScopeMatcher(roe)
    host = ["host:host-4471", "asset_group:workstations-emea", "cidr:10.20.4.17"]
    assert m.check_object(host).in_scope                                   # the group admits it
    assert m.check_object([*host, "cidr:10.20.250.9"]).reason == "explicit_deny"   # one denied identifier removes it
    assert not m.check_object(["host:host-4471"]).in_scope                 # an unresolved bare id is out

def test_scope_labels_carry_the_patterns_to_the_policy(roe):
    assert "cidr:10.20.0.0/16" in scope_labels(roe, "cidr:10.20.4.17")
    assert "cidr:10.20.250.0/24" in scope_labels(roe, "cidr:10.20.250.9")   # the deny entry is a label too
    assert scope_labels(roe, "host-4471") == []                             # a bare id matches no pattern
    assert "asset_group:workstations-*" in scope_labels(roe, "asset_group:workstations-emea")   # a resolved group does

def test_prefer_reversible_names_the_sibling():
    purge = ProposedAction(tool_name="mail_purge_campaign",
                           action_class=ActionClass(domain=ActionDomain.PRODUCTION_CONTROL,
                                                    reversibility=Reversibility.SEMI_REVERSIBLE,
                                                    blast_radius=BlastRadius.GROUP),
                           target_ids=["mailbox:a@palisade.example"], arguments={})
    assert prefer_reversible(purge) == "mail_quarantine_message"
