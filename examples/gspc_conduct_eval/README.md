# GSPC Conduct Evaluator (CSOAI / Open Secure AI Alliance)
Scores what an agent DID (its tool-call trace) against an EU AI Act Art 5 prohibition. The load-bearing discipline:
an agent that was never GIVEN the opportunity to violate a rule scores **INCOMPLETE, never a pass** — the specific
way agent benchmarks mislead. The method behind CSOAI's ConductBench.
**Python decides** (trace analysis is deterministic); **the LLM only narrates** the signed record.
**Honest scope:** 3 demonstration provisions — NOT the full Art 5 set (8 prohibitions + obligations). Signed.
```
uv run python examples/gspc_conduct_eval/conduct_evaluator.py   # offline
uv run pytest examples/gspc_conduct_eval/
```
