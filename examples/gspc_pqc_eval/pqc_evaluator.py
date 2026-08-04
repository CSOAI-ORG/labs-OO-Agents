# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# Contributed by CSOAI (csoai.org) — Council for the Safety of Artificial Intelligence.
"""GSPC PQC signing-agility evaluator — deterministic core, LLM-narrated report.

Scores a signing chain's post-quantum readiness against fixed criteria (does every
record NAME its algorithm? is the signature hybrid-ready? is it timestamped?). This
is the method behind CSOAI's PQCBench. Python decides — each criterion is a plain
boolean check over the record; the LLM only narrates the signed report.

Honest scope: 4 demonstration criteria over a toy chain — NOT the full PQCBench
standards matrix (NIST IR 8547, CNSA 2.0, RFC 9964). A chain with no records is
UNMEASURED, never a pass. Run offline with no API key:

    uv run python examples/gspc_pqc_eval/pqc_evaluator.py
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel

from nooa import Agent, hidden

with hidden:
    import hashlib
    import hmac
    import json
    import secrets
    from pathlib import Path

    from nooa.unifiedllm.fake import FakeLLMClient

CRITERIA = ("names_algorithm", "hybrid_ready", "timestamped", "tamper_evident")


class PQCReport(BaseModel):
    benchmark: Literal["GSPC-PQCBench-demo"] = "GSPC-PQCBench-demo"
    chain_id: str
    passed: list[str]
    failed: list[str]
    outcome: Literal["PASS", "PARTIAL", "FAIL", "UNMEASURED"]
    signature: str = ""


def _key() -> bytes:
    p = Path(__file__).parent / "gspc_pqc_signing_key.hex"
    if not p.exists():
        p.write_bytes(secrets.token_hex(32).encode()); p.chmod(0o600)
    return p.read_bytes()


class PQCEvaluator(Agent):
    """Scores a signing chain's PQC readiness; deterministic checks, LLM narrates."""

    def check_criterion(self, record: dict, name: str) -> bool:
        if name == "names_algorithm":
            return bool(record.get("alg"))
        if name == "hybrid_ready":
            return record.get("alg", "").upper().startswith(("ML-DSA", "SLH-DSA")) or record.get("hybrid") is True
        if name == "timestamped":
            return bool(record.get("timestamp") or record.get("rfc3161"))
        if name == "tamper_evident":
            return bool(record.get("signature") or record.get("hmac"))
        raise KeyError(name)

    def build_report(self, chain: list[dict]) -> PQCReport:
        if not chain:
            rep = PQCReport(chain_id="empty", passed=[], failed=list(CRITERIA), outcome="UNMEASURED")
        else:
            passed = [c for c in CRITERIA if all(self.check_criterion(r, c) for r in chain)]
            failed = [c for c in CRITERIA if c not in passed]
            outcome = "PASS" if not failed else ("FAIL" if not passed else "PARTIAL")
            cid = hashlib.sha256(json.dumps(chain, sort_keys=True).encode()).hexdigest()[:16]
            rep = PQCReport(chain_id=cid, passed=passed, failed=failed, outcome=outcome)
        body = rep.model_dump(exclude={"signature"})
        rep.signature = hmac.new(_key(), json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest()
        return rep

    def verify_report(self, rep: PQCReport) -> bool:
        body = rep.model_dump(exclude={"signature"})
        return hmac.compare_digest(
            hmac.new(_key(), json.dumps(body, sort_keys=True).encode(), hashlib.sha256).hexdigest(), rep.signature)

    def explain_report(self, rep: PQCReport) -> str:
        """Narrate this signed PQC-readiness report for an auditor. State which criteria
        passed and which failed, and what a FAIL means for post-quantum migration. Do not
        change any field. If UNMEASURED, say the chain had no records to score.
        """
        ...


if __name__ == "__main__":
    ev = PQCEvaluator(llm=FakeLLMClient())
    good = [{"alg": "ML-DSA-65", "timestamp": "2026-08-04", "signature": "abc", "hybrid": True}]
    weak = [{"alg": "Ed25519", "signature": "abc"}]
    for label, ch in [("PQC-ready", good), ("classical", weak), ("empty", [])]:
        r = ev.build_report(ch)
        print(f"{label:10} -> {r.outcome:10} passed={r.passed} verify={ev.verify_report(r)}")
