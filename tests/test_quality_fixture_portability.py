"""The disposable Dashboard fixture must not depend on a maintainer installation."""
import runpy
import sys
from pathlib import Path


def test_quality_fixture_uses_current_interpreter_by_default(monkeypatch):
    monkeypatch.delenv("HERMES_QUALITY_PYTHON", raising=False)
    fixture = runpy.run_path(str(Path(__file__).with_name("test_dashboard_live_authority_quality.py")))
    assert fixture["PYTHON"] == sys.executable


def test_quality_fixture_accepts_explicit_interpreter(monkeypatch, tmp_path):
    interpreter = str(tmp_path / "isolated-hermes-python")
    monkeypatch.setenv("HERMES_QUALITY_PYTHON", interpreter)
    fixture = runpy.run_path(str(Path(__file__).with_name("test_dashboard_live_authority_quality.py")))
    assert fixture["PYTHON"] == interpreter
