"""Runs the policy cases (tests/test_policy.py, plain Python) under pytest too."""

import importlib.util
import os

HERE = os.path.dirname(os.path.abspath(__file__))
_spec = importlib.util.spec_from_file_location("policy_cases", os.path.join(HERE, "test_policy.py"))
cases = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cases)


def test_policy_cases():
    for fn in cases.CASES:
        fn()
