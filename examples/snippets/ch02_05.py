from palisade.core.types import ScopeList


class Task(BaseModel):
    description: str
    sources: list[str]


class Plan(BaseModel):
    tasks: list[Task]


class Findings(BaseModel):
    timeline: list[str]
    cited_evidence: list[str]


def investigate(goal: str, lead_scope: ScopeList, run_id: str) -> Findings:
    plan = llm(f"Decompose this investigation into evidence-collection tasks, one per data source.\n{goal}", Plan)
    results = []
    for n, task in enumerate(plan.tasks):
        worker_scope = narrow(lead_scope, task.sources)         # subset of the lead's scope, or raise
        worker_id = f"spiffe://palisade.example/agent/investigate/worker/{n}"
        results.append(run_worker(worker_id, task, worker_scope, parent_run_id=run_id))
    return llm(f"Synthesize these findings into a timeline with cited evidence.\n{json.dumps(results)}", Findings)
