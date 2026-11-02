from pathlib import Path
from cryptography.hazmat.primitives import serialization
from palisade.roe import load_roe_yaml, sign_roe

key = serialization.load_pem_private_key(Path("~/.palisade/gov-roe-2026-10.pem").expanduser().read_bytes(), password=None)
roe = sign_roe(load_roe_yaml(Path("roe/eng_2026q4_soc_triage.yaml")), key, "gov-roe-2026-10")
Path("roe/signed/eng_2026q4_soc_triage.yaml").write_text(roe.model_dump_json(indent=2))
