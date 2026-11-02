# rt/pyrit_campaign.py (shape as of mid-2026; see the PyRIT docs for the current API)
from pyrit.prompt_target import HTTPTarget
from pyrit.score import SelfAskTrueFalseScorer

target = HTTPTarget(
    http_request=open("rt/triage_turn.http").read(),   # raw request template with {PROMPT}
    prompt_regex_string="{PROMPT}",
    callback_function=lambda resp: resp.json()["agent_text"],
)
scorer = SelfAskTrueFalseScorer(
    chat_target=scoring_model,          # a model on the offensive plane, under its own RoE
    true_false_question_path="rt/questions/proposed_out_of_vocab_action.yaml",
)
# An orchestrator (PromptSendingOrchestrator in older releases, attack classes in newer ones)
# sends each seed through converters (encodings, role framings) to the target and scores the
# responses; the campaign's seeds are categories from the RT matrix, not stored payload text.
