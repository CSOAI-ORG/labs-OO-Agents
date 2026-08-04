# SPDX-FileCopyrightText: Copyright (c) 2026, NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
# Contributed by CSOAI (csoai.org) — Council for the Safety of Artificial Intelligence.
"""Hermetic tests for PQCEvaluator — no network, FakeLLMClient only."""
import pytest
from nooa.unifiedllm.fake import FakeLLMClient
from pqc_evaluator import PQCEvaluator

@pytest.fixture
def ev(): return PQCEvaluator(llm=FakeLLMClient())
READY=[{"alg":"ML-DSA-65","timestamp":"2026-08-04","signature":"s","hybrid":True}]
WEAK=[{"alg":"Ed25519","signature":"s"}]

def test_pqc_ready_passes(ev): assert ev.build_report(READY).outcome=="PASS"
def test_classical_is_partial(ev): assert ev.build_report(WEAK).outcome=="PARTIAL"
def test_empty_chain_unmeasured(ev): assert ev.build_report([]).outcome=="UNMEASURED"
def test_report_signature_verifies(ev): assert ev.verify_report(ev.build_report(READY)) is True
def test_tampering_breaks_signature(ev):
    r=ev.build_report(READY); r.outcome="FAIL"; assert ev.verify_report(r) is False
