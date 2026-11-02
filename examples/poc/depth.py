"""poc/depth.py: does the product reason, or does it run a playbook?"""
import json, sys
from statistics import mean

verdicts = json.load(open(sys.argv[1]))
hyp = [len(v.get("hypotheses", [])) for v in verdicts]
qry = [len(v.get("query_log", [])) for v in verdicts]
shallow = [v["id"] for v, h, q in zip(verdicts, hyp, qry) if h < 2 or q == 0]
print(f"verdicts={len(verdicts)} mean_hypotheses={mean(hyp):.2f} mean_queries={mean(qry):.2f}")
print(f"shallow: {len(shallow)} -> {shallow[:10]}")
