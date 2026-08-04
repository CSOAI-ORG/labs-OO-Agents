# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# Contributed by CSOAI (csoai.org) — Council for the Safety of Artificial Intelligence.
"""Hermetic tests for ProvenanceEvaluator — no network, FakeLLMClient only."""

import pytest

from nooa.unifiedllm.fake import FakeLLMClient
from provenance_evaluator import ProvenanceEvaluator

MARKED = b"\x89PNG data\x00MANIFEST{c2pa}"
UNMARKED = b"\x89PNG data-only"


@pytest.fixture
def ev():
    return ProvenanceEvaluator(llm=FakeLLMClient())


def test_identity_control_survives(ev):
    assert ev.check_survival(MARKED, "identity") == "SURVIVED"


def test_screenshot_destroys_marking(ev):
    assert ev.check_survival(MARKED, "screenshot") == "DESTROYED"


def test_unmarked_asset_is_unmeasured(ev):
    # no marking present -> never claim a pass
    assert ev.check_survival(UNMARKED, "identity") == "UNMEASURED"


def test_record_signature_verifies(ev):
    assert ev.verify_record(ev.build_record(MARKED, "reencode")) is True


def test_tampering_breaks_signature(ev):
    rec = ev.build_record(MARKED, "identity")
    rec.outcome = "DESTROYED"  # flip the result
    assert ev.verify_record(rec) is False


def test_strict_narration_refuses_unmeasured(ev):
    ev.strict_narration = True
    rec = ev.build_record(UNMARKED, "screenshot")  # UNMEASURED
    with pytest.raises(ValueError):
        ev.explain_record(rec)
