# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# Contributed by CSOAI (csoai.org) — Council for the Safety of Artificial Intelligence.
"""GSPC provenance-survival evaluator — deterministic core, LLM-narrated records.

Companion to gspc_provision_eval. Same pattern CSOAI contributes to the Open
Secure AI Alliance's "evaluations and benchmarks" lane:

    Python decides. The LLM only narrates.

Where the provision evaluator scores a *scenario* against statute, this scores
whether an AI-content *provenance marking survives a transform* — the
deterministic evidence behind the EU AI Act Art 50(2) machine-readable-marking
obligation. Applying transforms, checking survival, building the record, and
signing it are ordinary deterministic Python — no model in the loop, no
fabricated precision: an asset with no marking to test is UNMEASURED, never a
pass. An optional generation method (`explain_record`) lets an LLM narrate the
signed record; the deterministic layer never depends on it.

Run (deterministic only, no API key needed):

    uv run python examples/gspc_provenance_eval/provenance_evaluator.py

With OPENAI_API_KEY or NVIDIA_API_KEY set, the example additionally calls
`explain_record` for a live LLM narration of the signed record.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field

from nooa import Agent, hidden

with hidden:
    import hashlib
    import hmac
    import json
    import os
    import secrets

    from nooa.unifiedllm.fake import FakeLLMClient

# ---------------------------------------------------------------------------
# Transform set
#
# Four representative byte transforms for demonstration. This is NOT the full
# ProvBench battery (9 non-control transforms); see README.md. A "marking" is
# an appended MANIFEST block — a demonstration stand-in for a real C2PA
# manifest, not a C2PA parser. `identity` is the control: a marking MUST
# survive it or the rig is broken.
# ---------------------------------------------------------------------------
_SENTINEL = b"\x00MANIFEST"


def _t_identity(b: bytes) -> bytes:
    return b


def _t_strip_metadata(b: bytes) -> bytes:
    return b.split(_SENTINEL, 1)[0]


def _t_reencode(b: bytes) -> bytes:
    return b.split(_SENTINEL, 1)[0]


def _t_screenshot(b: bytes) -> bytes:
    # a screenshot-equivalent rasterise loses ALL container metadata
    return b.split(_SENTINEL, 1)[0]


TRANSFORMS = {
    "identity": _t_identity,
    "strip_metadata": _t_strip_metadata,
    "reencode": _t_reencode,
    "screenshot": _t_screenshot,
}


class ProvenanceRecord(BaseModel):
    """A signed, tamper-evident provenance-survival record."""

    benchmark: Literal["GSPC-ProvBench-demo"] = "GSPC-ProvBench-demo"
    asset_sha256: str
    transform: str
    outcome: Literal["SURVIVED", "DESTROYED", "UNMEASURED"]
    signature: str = Field(default="")


def _key_path() -> str:
    return str(Path(__file__).parent / "gspc_prov_signing_key.hex")


def _signing_key() -> bytes:
    p = _key_path()
    if not os.path.exists(p):
        k = secrets.token_hex(32).encode()
        with open(p, "wb") as f:
            f.write(k)
        os.chmod(p, 0o600)
        return k
    return open(p, "rb").read()


class ProvenanceEvaluator(Agent):
    """Scores whether a provenance marking survives a transform, and signs the record.

    Deterministic methods (`apply_transform`, `check_survival`, `build_record`,
    `verify_record`) are plain Python. `explain_record` is the only generation
    method — it narrates the signed record without altering it.
    """

    strict_narration: bool = False

    # --- deterministic core (no model) -------------------------------------
    def apply_transform(self, asset: bytes, transform: str) -> bytes:
        if transform not in TRANSFORMS:
            raise KeyError(f"unknown transform {transform!r}")
        return TRANSFORMS[transform](asset)

    def check_survival(self, asset: bytes, transform: str) -> str:
        if _SENTINEL not in asset:
            return "UNMEASURED"  # no marking to test — never claim a pass
        out = self.apply_transform(asset, transform)
        return "SURVIVED" if _SENTINEL in out else "DESTROYED"

    def build_record(self, asset: bytes, transform: str) -> ProvenanceRecord:
        rec = ProvenanceRecord(
            asset_sha256=hashlib.sha256(asset).hexdigest(),
            transform=transform,
            outcome=self.check_survival(asset, transform),
        )
        body = rec.model_dump(exclude={"signature"})
        rec.signature = hmac.new(
            _signing_key(), json.dumps(body, sort_keys=True).encode(), hashlib.sha256
        ).hexdigest()
        return rec

    def verify_record(self, rec: ProvenanceRecord) -> bool:
        body = rec.model_dump(exclude={"signature"})
        expect = hmac.new(
            _signing_key(), json.dumps(body, sort_keys=True).encode(), hashlib.sha256
        ).hexdigest()
        return hmac.compare_digest(expect, rec.signature)

    # --- the ONLY generation method (LLM narrates; never decides) ----------
    def explain_record(self, rec: ProvenanceRecord) -> str:
        """Narrate this signed provenance record for an auditor in plain English.

        Report the transform, the outcome, and what a DESTROYED outcome means for an
        Art 50(2) marking. Do not change any field. If the outcome is UNMEASURED, say
        plainly that no marking was present to test — do not imply a pass.
        """
        if self.strict_narration and rec.outcome == "UNMEASURED":
            raise ValueError("strict_narration: refusing to narrate an UNMEASURED record")
        ...


if __name__ == "__main__":
    ev = ProvenanceEvaluator(llm=FakeLLMClient())
    marked = b"\x89PNG fake-image-bytes\x00MANIFEST{c2pa:sig}"
    for t in TRANSFORMS:
        r = ev.build_record(marked, t)
        print(f"{t:14} -> {r.outcome:10} verify={ev.verify_record(r)}")
    unmarked = b"\x89PNG fake-image-bytes-no-manifest"
    print("unmarked ->", ev.build_record(unmarked, "screenshot").outcome, "(UNMEASURED = safe default)")
