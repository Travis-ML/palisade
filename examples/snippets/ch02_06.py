class SigmaRule(BaseModel):
    yaml: str


class Critique(BaseModel):
    over_broad_clauses: list[str]
    missed_cases: list[str]
    suggestion: str


def draft_detection(hypothesis: str, corpus, max_rounds: int = 5) -> SigmaRule | None:
    rule = llm(f"Draft a Sigma rule that detects: {hypothesis}", SigmaRule)
    for _ in range(max_rounds):
        score = corpus.evaluate(rule.yaml)            # precision, recall, over-broad matches: machine-checked
        if score.precision >= 0.95 and score.recall >= 0.90 and score.over_broad_matches == 0:
            return rule
        critique = llm(f"Critique this rule against these results. Flag any clause that matches benign "
                       f"events.\n{rule.yaml}\n{score.model_dump_json()}", Critique)
        rule = llm(f"Revise the rule.\n{rule.yaml}\nCritique:\n{critique.model_dump_json()}", SigmaRule)
    return None                                       # did not converge: route to human review, do not ship
