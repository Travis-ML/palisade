from palisade.guardrails.input import CanaryRegistry, InjectionScreen

canaries = CanaryRegistry()
screen = InjectionScreen(tool_names=registry.keys(), classifier=my_classifier, canaries=canaries)
tagged = screen.screen_tagged(desc)
# tagged.screening -> ScreeningResult(flagged=True, pattern_hits=['tool_invocation_in_data'], classifier_score=0.83, canary_hits=[])
