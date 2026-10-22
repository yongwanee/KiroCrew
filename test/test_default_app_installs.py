"""``AppsLoader.default_installed_apps()``: edition-declared registry installs.

The pass records an execution grant on the operator's behalf, so most of this
file pins its boundary: it installs only from a registry the build pins at the
``owner`` tier, binds the grant to the exact repository that registry's row
names, never overwrites an operator's grant, rolls back what it added when the
install fails, and never touches an app again once it has handled it.
"""

from __future__ import annotations

import dataclasses
import json

import pytest

from kiro_crew.apps import default_installs as di
from kiro_crew.apps import execution as exec_mod
from kiro_crew.apps import manager as manager_mod
from kiro_crew.apps import registry as reg_mod
from kiro_crew.config.loader import KiroCrewConfig, _invalidate_config_cache, config_path
from kiro_crew.platform.bootstrap import build_default_context
from kiro_crew.platform.defaults import DefaultAppsLoader

REGISTRY_REPO = "https://forge.example.com/org/app-registry.git"
APP_REPO = "https://forge.example.com/org/chorus-app.git"
OTHER_REPO = "https://forge.example.com/org/someone-else.git"


class _Loader(DefaultAppsLoader):
    def __init__(self, installs, registries) -> None:
        self._installs = installs
        self._registries = registries

    def default_installed_apps(self):
        return self._installs

    def default_registries(self):
        return self._registries


def _pinned(trust: str = "owner") -> list[dict]:
    return [{"name": "internal", "repo": REGISTRY_REPO, "branch": "main", "trust": trust}]


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("KIROCREW_HOME", str(tmp_path))
    _invalidate_config_cache()
    yield tmp_path
    _invalidate_config_cache()


class _World:
    """The registry, install and app-record seams the pass reaches, all faked."""

    def __init__(self, monkeypatch, *, installs, registries, entry=None, install_ok=True):
        ctx = dataclasses.replace(
            build_default_context(KiroCrewConfig()), apps_loader=_Loader(installs, registries)
        )
        monkeypatch.setattr(di, "current_context", lambda: ctx)
        monkeypatch.setattr(reg_mod, "current_context", lambda: ctx)
        self.installed: set[str] = set()
        self.install_calls: list[str] = []
        self.refreshed: list[str] = []
        self.install_ok = install_ok
        self.entry = entry

        async def _refresh(repo=None):
            self.refreshed.append(repo)
            return {"ok": True}

        async def _install(name):
            self.install_calls.append(name)
            if self.install_ok:
                self.installed.add(name)
                return {"ok": True, "name": name}
            return {"ok": False, "name": name, "error": "build failed"}

        monkeypatch.setattr(reg_mod, "refresh_registries", _refresh)
        monkeypatch.setattr(reg_mod, "get_registry_app", lambda name: self.entry)
        monkeypatch.setattr(di, "_install_transaction", _install)
        monkeypatch.setattr(
            manager_mod, "get_app", lambda name: {"name": name} if name in self.installed else None
        )
        monkeypatch.setattr(exec_mod, "builtin_app_names", lambda: frozenset({"projects"}))


def _entry(registry: str = "internal", repo: str = APP_REPO) -> dict:
    return {"name": "chorus", "repo": repo, "branch": "main", "_registry": registry}


def _agent() -> dict:
    path = config_path()
    if not path.is_file():
        return {}
    return json.loads(path.read_text()).get("agent", {})


def _seed_agent(agent: dict) -> None:
    config_path().parent.mkdir(parents=True, exist_ok=True)
    config_path().write_text(json.dumps({"agent": agent}))
    _invalidate_config_cache()


ROW = [{"name": "chorus", "registry": "internal"}]


@pytest.mark.asyncio
async def test_public_default_declares_nothing_and_writes_nothing(home, monkeypatch):
    _World(monkeypatch, installs=[], registries=[])
    assert DefaultAppsLoader().default_installed_apps() == []
    assert await di.reconcile_default_installs() == {}
    assert not config_path().exists()


@pytest.mark.asyncio
async def test_installs_once_with_a_grant_bound_to_the_registry_row(home, monkeypatch):
    world = _World(monkeypatch, installs=ROW, registries=_pinned(), entry=_entry())

    assert await di.reconcile_default_installs() == {"chorus": "installed"}

    agent = _agent()
    assert agent["apps_trusted"] == ["chorus"]
    assert agent["apps_trusted_repositories"] == {"chorus": reg_mod._normalize_git_target(APP_REPO)}
    assert agent["apps_default_installs_applied"] == ["chorus"]
    assert world.refreshed == [REGISTRY_REPO]
    assert world.install_calls == ["chorus"]


@pytest.mark.asyncio
async def test_an_uninstalled_app_is_never_reinstalled(home, monkeypatch):
    world = _World(monkeypatch, installs=ROW, registries=_pinned(), entry=_entry())
    await di.reconcile_default_installs()
    world.installed.clear()  # the operator uninstalled it

    assert await di.reconcile_default_installs() == {}
    assert world.install_calls == ["chorus"]


@pytest.mark.asyncio
async def test_an_already_installed_app_is_marked_and_left_alone(home, monkeypatch):
    world = _World(monkeypatch, installs=ROW, registries=_pinned(), entry=_entry())
    world.installed.add("chorus")

    assert await di.reconcile_default_installs() == {"chorus": "already_installed"}
    agent = _agent()
    assert agent["apps_default_installs_applied"] == ["chorus"]
    assert "apps_trusted" not in agent
    assert world.install_calls == []


@pytest.mark.parametrize(
    "registries",
    [
        [],  # the named registry is not pinned at all
        _pinned(trust="index"),  # pinned, but credential-free
    ],
)
@pytest.mark.asyncio
async def test_a_registry_the_build_does_not_pin_at_owner_is_refused(home, monkeypatch, registries):
    world = _World(monkeypatch, installs=ROW, registries=registries, entry=_entry())

    assert await di.reconcile_default_installs() == {"chorus": "refused_registry"}
    assert _agent() == {}
    assert world.install_calls == []


@pytest.mark.asyncio
async def test_a_same_named_row_from_another_registry_is_refused(home, monkeypatch):
    world = _World(monkeypatch, installs=ROW, registries=_pinned(), entry=_entry(registry=""))

    assert await di.reconcile_default_installs() == {"chorus": "refused_source"}
    assert _agent() == {}
    assert world.install_calls == []


@pytest.mark.asyncio
async def test_a_builtin_name_is_refused(home, monkeypatch):
    rows = [{"name": "projects", "registry": "internal"}]
    world = _World(monkeypatch, installs=rows, registries=_pinned(), entry=_entry())

    assert await di.reconcile_default_installs() == {"projects": "refused_builtin"}
    assert _agent() == {}
    assert world.install_calls == []


@pytest.mark.asyncio
async def test_an_operator_grant_to_another_repository_is_never_overwritten(home, monkeypatch):
    other = reg_mod._normalize_git_target(OTHER_REPO)
    _seed_agent({"apps_trusted": ["chorus"], "apps_trusted_repositories": {"chorus": other}})
    world = _World(monkeypatch, installs=ROW, registries=_pinned(), entry=_entry())

    assert await di.reconcile_default_installs() == {"chorus": "refused_existing_grant"}
    agent = _agent()
    assert agent["apps_trusted_repositories"] == {"chorus": other}
    assert "apps_default_installs_applied" not in agent
    assert world.install_calls == []


@pytest.mark.asyncio
async def test_a_failed_install_rolls_back_the_grant_and_retries_next_boot(home, monkeypatch):
    world = _World(
        monkeypatch, installs=ROW, registries=_pinned(), entry=_entry(), install_ok=False
    )

    assert await di.reconcile_default_installs() == {"chorus": "install_failed"}
    agent = _agent()
    assert agent["apps_trusted"] == []
    assert agent["apps_trusted_repositories"] == {}
    assert "apps_default_installs_applied" not in agent

    world.install_ok = True
    assert await di.reconcile_default_installs() == {"chorus": "installed"}
    assert world.install_calls == ["chorus", "chorus"]


@pytest.mark.asyncio
async def test_a_failed_install_keeps_an_operator_legacy_grant(home, monkeypatch):
    _seed_agent({"apps_trusted": ["chorus"]})
    _World(monkeypatch, installs=ROW, registries=_pinned(), entry=_entry(), install_ok=False)

    assert await di.reconcile_default_installs() == {"chorus": "install_failed"}
    agent = _agent()
    assert agent["apps_trusted"] == ["chorus"]
    assert agent["apps_trusted_repositories"] == {}


@pytest.mark.asyncio
async def test_a_corrupt_config_installs_nothing(home, monkeypatch):
    # The loader reads a corrupt file as defaults, so the applied list looks
    # empty. What keeps an uninstalled app from coming back is that the grant
    # write refuses a corrupt file, and install runs only after that write.
    config_path().parent.mkdir(parents=True, exist_ok=True)
    config_path().write_text("{not json")
    _invalidate_config_cache()
    world = _World(monkeypatch, installs=ROW, registries=_pinned(), entry=_entry())

    assert await di.reconcile_default_installs() == {"chorus": "error"}
    assert world.install_calls == []
    assert config_path().read_text() == "{not json"


@pytest.mark.asyncio
async def test_an_unreadable_applied_list_installs_nothing(home, monkeypatch):
    world = _World(monkeypatch, installs=ROW, registries=_pinned(), entry=_entry())

    def _boom():
        raise OSError("unreadable")

    monkeypatch.setattr(di, "_applied_names", _boom)

    assert await di.reconcile_default_installs() == {}
    assert world.install_calls == []


@pytest.mark.parametrize(
    "bogus",
    ["chorus", {"name": "chorus"}, [{"name": "../x", "registry": "internal"}], [{"name": "a"}]],
)
@pytest.mark.asyncio
async def test_malformed_rows_are_dropped(home, monkeypatch, bogus):
    world = _World(monkeypatch, installs=bogus, registries=_pinned(), entry=_entry())

    assert await di.reconcile_default_installs() == {}
    assert world.install_calls == []


def test_the_applied_marker_survives_a_config_round_trip(home):
    _seed_agent({"apps_default_installs_applied": ["chorus", 5, ""]})
    assert KiroCrewConfig.load().agent.apps_default_installs_applied == ["chorus"]
