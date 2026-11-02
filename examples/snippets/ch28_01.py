from pathlib import Path
from palisade.capabilities.loader import load_capability
m = load_capability(Path("capabilities/cert_expiry_remediation/capability.yaml"))
print("loaded", m.name, m.version, m.plane.value, [c.action_class.key() for c in m.ceilings])
