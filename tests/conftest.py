"""Import the plugin as the package Hermes loads it as, from wherever pytest was started."""

import sys
import importlib.util
from pathlib import Path

import pytest

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("cozychat", root / "__init__.py",
                                            submodule_search_locations=[str(root)])
package = importlib.util.module_from_spec(spec)
sys.modules["cozychat"] = package
spec.loader.exec_module(package)


@pytest.fixture(autouse=True)
def shared_state(tmp_path):
    """A shared-state directory of this test's own, for every test in this suite.

    Autouse because the feed, the desk and the card registry all reach `state.shared_state()` when
    nobody hands them one — which is how the real plugin wires them — so a test that constructed a
    bare `LiveFeed()` without this would write into the developer's own `~/.hermes/cozychat`.
    """
    from cozychat import state

    store = state.configure(tmp_path / "cozychat")
    yield store
    store.close()
    state.configure(tmp_path / "cozychat-unused")


@pytest.fixture
def plugin_app(monkeypatch):
    """The real dashboard router, with a package stub standing in for the loaded plugin.

    Shared by the feed's route tests and the approvals' because they mount the SAME router: two
    copies of this would be two chances to stub a plugin the real loader does not resemble.
    Returns `(TestClient, package, api module)`; the caller puts what it needs on the package,
    exactly as `register()` puts the real ones on the real one.
    """
    import importlib.util
    import pathlib
    import types

    pytest.importorskip("fastapi")
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    import cozychat
    from cozychat.approvals import ApprovalDesk
    from cozychat.feed import LiveFeed

    feed, desk = LiveFeed(), ApprovalDesk()
    package = types.ModuleType("hermes_plugins.cozychat")
    package.VERSION = "0.2.0"
    package.STATE_VERSION = "shared-v1"
    package.live_feed = lambda: feed
    package.approval_desk = lambda: desk
    package.transport_selected = lambda: False
    package.feed, package.desk = feed, desk
    monkeypatch.setitem(sys.modules, "hermes_plugins.cozychat", package)

    api_path = pathlib.Path(cozychat.__file__).parent / "dashboard" / "api.py"
    spec = importlib.util.spec_from_file_location("hermes_dashboard_plugin_cozychat", api_path)
    api = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, "hermes_dashboard_plugin_cozychat", api)
    spec.loader.exec_module(api)

    app = FastAPI()
    app.include_router(api.router, prefix="/api/plugins/cozychat")
    return TestClient(app), package, api


@pytest.fixture(autouse=True)
def hermes_secret_scope(monkeypatch):
    """A stand-in for ``agent.secret_scope`` (D34): the plugin reads credentials only through it.

    Real Hermes builds a profile's scope from its own ``.env``; this stub does the same for a test's
    scratch home. The plugin itself never opens ``.env``. Tests that need the module absent set
    ``sys.modules["agent.secret_scope"] = None``.
    """
    import types

    agent = types.ModuleType("agent")
    scope = types.ModuleType("agent.secret_scope")

    def build(home):
        values = {}
        try:
            lines = (Path(home) / ".env").read_text("utf-8").splitlines()
        except OSError:
            lines = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                name, _, value = line.removeprefix("export ").partition("=")
                values[name.strip()] = value.strip().strip("'\"")
        return values

    scope.build_profile_secret_scope = build
    agent.secret_scope = scope
    monkeypatch.setitem(sys.modules, "agent", agent)
    monkeypatch.setitem(sys.modules, "agent.secret_scope", scope)
