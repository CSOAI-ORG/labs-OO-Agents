# GSPC PQC Evaluator (CSOAI / Open Secure AI Alliance)
Scores a signing chain's post-quantum readiness against fixed criteria — the method behind CSOAI's PQCBench.
**Python decides** (each criterion is a boolean check over the records); **the LLM only narrates** the signed report.
Records with no chain return `UNMEASURED`, never a pass. Signed (HMAC-SHA256, 0600 key, git-ignored).
**Honest scope:** 4 demonstration criteria over a toy chain — NOT the full PQCBench standards matrix (NIST IR 8547,
CNSA 2.0, RFC 9964). CSOAI's real PQCBench scores 5 signing chains; SIGIL v2 reaches 4/5 with real ML-DSA-65 + RFC 3161.
```
uv run python examples/gspc_pqc_eval/pqc_evaluator.py   # offline
uv run pytest examples/gspc_pqc_eval/
```
