import yaml
from pydantic import ValidationError
p = Path("capabilities/cert_expiry_remediation/capability.yaml")
good = yaml.safe_load(p.read_text())

def attempt(label, mutate):
    doc = yaml.safe_load(yaml.safe_dump(good)); mutate(doc)
    p.write_text(yaml.safe_dump(doc))
    try:
        load_capability(p); print(f"{label}: LOADED (unexpected)")
    except ValidationError as e:
        print(f"{label}: refused -> {e.errors()[0]['msg']}")

attempt("ceiling above taxonomy", lambda d: d["ceilings"][2].update({"max_tier": 5}))                 # production control at 5
attempt("irreversible without approval", lambda d: (d["tools"][2]["action_class"].update({"reversibility": "irreversible"}),
                                                    d["ceilings"][2]["action_class"].update({"reversibility": "irreversible"}),
                                                    d["ceilings"][2].update({"max_tier": 3}),           # keep the ceiling legal so A7 is what fires
                                                    d["required_gates"][2]["action_class"].update({"reversibility": "irreversible"})))
attempt("offense tool on defensive plane", lambda d: d["tools"].append({"name": "range_emulate_step", "server": "palisade-range",
        "version": "1.0.0", "description_sha256": "0" * 64,
        "action_class": {"domain": "offense", "reversibility": "reversible", "blast_radius": "single"}}))
attempt("no human owner", lambda d: d["owner"].update({"human": "  "}))
p.write_text(yaml.safe_dump(good))
