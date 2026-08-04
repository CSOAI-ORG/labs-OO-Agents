# GSPC Provenance Evaluator (CSOAI / Open Secure AI Alliance)

A NOOA agent that measures whether an AI-content **provenance marking survives a transform** —
the deterministic evidence behind the EU AI Act Art 50(2) machine-readable-marking obligation.
Companion example to `gspc_provision_eval`.

## The split (idiomatic NOOA)
- **Python decides.** `apply_transform`, `check_survival`, `build_record`, `verify_record` are
  ordinary deterministic methods (no `...` body). A marking survived a transform or it did not —
  no model judgement. Anything with no marking to test returns `UNMEASURED`, never a pass.
- **The LLM narrates.** `explain_record` is the only generation method (`...` body, docstring =
  prompt). It narrates the signed record without altering it; `strict_narration=True` makes it
  refuse to narrate an `UNMEASURED` record. Remove the model and nothing measured changes.

## Signed, tamper-evident records
Every `ProvenanceRecord` carries an HMAC-SHA256 signature over its canonical JSON, keyed with a
local `0600` key file (git-ignored). `verify_record` recomputes it; flipping any field breaks it.

## Honest scope
The built-in transform set is **4 representative operations** for the example — **not** the full
9-transform ProvBench battery, and the marking model (an appended MANIFEST block) is a demonstration
stand-in, not a C2PA parser. The architecture — deterministic survival scoring, signed records,
`UNMEASURED` default — is what CSOAI's public **ProvBench** publishes at scale: *0 of 20 assets
survived* a real transform battery (95% CI, clustered by asset). This is a corpus question, not a
code question, and the full corpus is out of scope for this example.

## Run
```
uv run python examples/gspc_provenance_eval/provenance_evaluator.py   # offline, no API key
uv run pytest examples/gspc_provenance_eval/                          # hermetic
```
