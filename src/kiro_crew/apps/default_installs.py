"""Install the registry apps an edition ships as defaults, once each.

``AppsLoader.default_installed_apps()`` names apps by ``{name, registry}``. After
the dashboard listener serves, :func:`reconcile_default_installs` installs each
named app that has never been handled before, through the same transaction the
App Store's install button runs, and records the name in
``agent.apps_default_installs_applied`` so it is never handled again.

Three properties carry the design, and each has a test:

- **The edition names an app, never a repository.** The clone coordinates come
  from the row the named registry publishes, and the named registry must be one
  the build pins at the ``owner`` tier. A row whose resolved entry comes from a
  different registry (a same-named public app, an operator registry) is refused.
- **The execution grant is the one the consent dialog would record.** It binds
  the app name to the exact repository the registry row names, in the same
  ``agent.apps_trusted`` / ``apps_trusted_repositories`` keys, so a later
  repository change re-prompts like any other grant. A pre-existing grant to a
  DIFFERENT repository is never overwritten.
- **One attempt that succeeds, then hands off.** The applied marker lives in
  ``config.json``, the file that already holds the grants and that the sandbox
  seals read-only, so an uninstalled or disabled app stays that way. An app
  already installed is marked without being touched. A failed install rolls back
  the grant this pass added and leaves the name unmarked, so the next boot
  retries.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from kiro_crew.platform import PlatformCompositionError, current_context, safe_context_call
from kiro_crew.sel import sel

logger = logging.getLogger(__name__)

#: Upper bound on the rows one boot will act on. The list is build-authored, so
#: this only bounds a companion bug, not an attacker.
_MAX_DEFAULT_INSTALLS = 32

_APPLIED_KEY = "apps_default_installs_applied"


def _declared_rows() -> list[tuple[str, str]]:
    """The edition's ``(name, registry)`` pairs, malformed rows dropped and logged."""
    empty: list[dict[str, Any]] = []
    raw: Any = safe_context_call(
        lambda: current_context().apps_loader.default_installed_apps(),
        fallback=empty,
        log_message="edition default_installed_apps() unavailable",
    )
    if not raw:
        return []
    if isinstance(raw, (str, bytes, dict)) or not hasattr(raw, "__iter__"):
        logger.error(
            "Ignoring a malformed default_installed_apps() return of type %s",
            type(raw).__name__,
        )
        return []
    from kiro_crew.apps.execution import APP_NAME_RE

    rows: list[tuple[str, str]] = []
    seen: set[str] = set()
    for row in list(raw)[:_MAX_DEFAULT_INSTALLS]:
        if not isinstance(row, dict):
            logger.error("Ignoring a non-object default install row: %s", type(row).__name__)
            continue
        name = row.get("name")
        registry = row.get("registry")
        if not isinstance(name, str) or not APP_NAME_RE.fullmatch(name):
            logger.error("Ignoring a default install row with an invalid app name: %r", name)
            continue
        if not isinstance(registry, str) or not registry.strip():
            logger.error("Ignoring default install %r: it names no registry", name)
            continue
        if name in seen:
            continue
        seen.add(name)
        rows.append((name, registry.strip()))
    return rows


def _owner_pinned_registry(registry: str) -> Any | None:
    """The build-pinned registry row named *registry*, if it is at the owner tier."""
    from kiro_crew.apps import registry as reg_mod

    for reg in reg_mod._pinned_registries():
        if reg_mod._public_registry_name(reg) != registry:
            continue
        if reg_mod._registry_trust_tier_of(reg) != reg_mod._TRUST_OWNER:
            return None
        return reg
    return None


def _applied_names() -> frozenset[str]:
    """Names already handled, read from the effective config.

    Raises when the config cannot be read: "unknown" must mean "install nothing",
    never "nothing was applied", or an unreadable file would reinstall apps the
    operator removed.
    """
    from kiro_crew.config.loader import KiroCrewConfig

    raw = getattr(KiroCrewConfig.load().agent, _APPLIED_KEY, [])
    return frozenset(a for a in raw if isinstance(a, str)) if isinstance(raw, list) else frozenset()


def _write_agent(mutate: Any) -> None:
    """One locked read-modify-write of the base ``config.json`` ``agent`` section.

    Same shape as the trusted-apps writers: a targeted edit of the raw base
    document under ``update_config_locked``, which refuses a corrupt file rather
    than replacing it with defaults, then a cache invalidation so the next gate
    read sees the change without a restart.
    """
    from kiro_crew.config.loader import _invalidate_config_cache, config_path, update_config_locked

    def _apply(raw: dict) -> dict | None:
        agent_raw = raw.get("agent")
        if not isinstance(agent_raw, dict):
            agent_raw = {}
            raw["agent"] = agent_raw
        if mutate(agent_raw) is False:
            return None
        return raw

    update_config_locked(config_path(), mutate=_apply, stamp_meta=False)
    _invalidate_config_cache()


def _list(agent_raw: dict, key: str) -> list[str]:
    value = agent_raw.get(key)
    return [a for a in value if isinstance(a, str) and a] if isinstance(value, list) else []


def _mark_applied(name: str) -> None:
    def _mutate(agent_raw: dict) -> bool:
        applied = _list(agent_raw, _APPLIED_KEY)
        if name in applied:
            return False
        applied.append(name)
        agent_raw[_APPLIED_KEY] = applied
        return True

    _write_agent(_mutate)


def _grant(name: str, repository: str) -> None:
    """Record the repository-bound execution grant the consent dialog would record."""

    def _mutate(agent_raw: dict) -> None:
        trusted = _list(agent_raw, "apps_trusted")
        if name not in trusted:
            trusted.append(name)
        agent_raw["apps_trusted"] = trusted
        repositories = agent_raw.get("apps_trusted_repositories")
        bindings = dict(repositories) if isinstance(repositories, dict) else {}
        bindings[name] = repository
        agent_raw["apps_trusted_repositories"] = bindings
        agent_raw["apps_trusted_local"] = [
            a for a in _list(agent_raw, "apps_trusted_local") if a != name
        ]

    _write_agent(_mutate)


def _revoke(name: str, *, drop_name: bool) -> None:
    """Undo :func:`_grant` after a failed install. Only called when this pass added it.

    *drop_name* is False when the operator already held a legacy name-only grant
    before this pass: only the repository binding this pass added is removed, so a
    failed default install never withdraws consent the operator gave.
    """

    def _mutate(agent_raw: dict) -> None:
        if drop_name:
            agent_raw["apps_trusted"] = [a for a in _list(agent_raw, "apps_trusted") if a != name]
        repositories = agent_raw.get("apps_trusted_repositories")
        if isinstance(repositories, dict):
            bindings = dict(repositories)
            bindings.pop(name, None)
            agent_raw["apps_trusted_repositories"] = bindings

    _write_agent(_mutate)


def _audit(name: str, outcome: str, detail: str) -> None:
    try:
        sel().log_api_access(
            caller="edition_default_install",
            operation="app_default_install",
            outcome=outcome,
            resources=f"{name}={detail}",
        )
    except Exception:  # noqa: BLE001 - losing the audit line must not change the outcome
        logger.warning("could not audit the default install of %r", name, exc_info=True)


async def _install_transaction(name: str) -> dict[str, Any]:
    """The App Store install button's transaction, minus the HTTP request.

    Mirrors ``routes_registry.handle_registry_install``: install, then register and
    start the backend, or suspend when the app needs session-approval re-consent.
    The caller holds ``app_lifecycle_lock(name)``.
    """
    from kiro_crew.apps.registry import install_from_registry
    from kiro_crew.apps.routes_lifecycle import (
        _app_may_run_after_install,
        _register_app_off_loop,
        _start_backend_after_install,
        _suspend_app_for_session_approval_reconsent,
    )

    result = await install_from_registry(name)
    if not result.get("ok") or result.get("needsClientInstall"):
        return result
    if await _app_may_run_after_install(result["name"], fresh_install=True):
        await _register_app_off_loop(result["name"])
        await _start_backend_after_install(result["name"])
    else:
        await _suspend_app_for_session_approval_reconsent(result["name"])
    return result


async def _install_one(name: str, registry: str) -> str:
    """Handle one declared app. Returns a short outcome tag (logged and tested)."""
    from kiro_crew.apps import registry as reg_mod
    from kiro_crew.apps.execution import (
        builtin_app_names,
        trusted_app_names,
        trusted_app_repository,
    )
    from kiro_crew.apps.manager import app_lifecycle_lock, get_app

    if name in await asyncio.to_thread(builtin_app_names):
        logger.error("Default install %r names a built-in app; refusing", name)
        return "refused_builtin"

    reg = await asyncio.to_thread(_owner_pinned_registry, registry)
    if reg is None:
        logger.error(
            "Default install %r names registry %r, which this build does not pin at the "
            "owner tier; refusing",
            name,
            registry,
        )
        return "refused_registry"

    async with app_lifecycle_lock(name):
        if await asyncio.to_thread(get_app, name) is not None:
            # Already installed, by the operator or an earlier build. Hand off
            # without touching its enabled state or its grant.
            await asyncio.to_thread(_mark_applied, name)
            return "already_installed"

        # Fresh index for the one registry the row names, so the coordinates the
        # grant binds are the ones install is about to clone.
        await reg_mod.refresh_registries(repo=reg.repo)
        entry = await asyncio.to_thread(reg_mod.get_registry_app, name)
        if not entry or entry.get("_registry") != registry:
            logger.error(
                "Default install %r: the row that resolves for this name is not from "
                "registry %r; refusing",
                name,
                registry,
            )
            return "refused_source"
        git_url = reg_mod._entry_git_url(entry)
        if not git_url or reg_mod._git_target_is_unsupported(git_url):
            return "refused_source"
        repository = reg_mod._normalize_git_target(git_url)

        existing = await asyncio.to_thread(trusted_app_repository, name)
        if existing and existing != repository:
            # The operator consented to a different repository under this name.
            # Never overwrite their decision; leave it unmarked so it is visible.
            logger.error(
                "Default install %r: an existing trust grant names a different "
                "repository; leaving it to the operator",
                name,
            )
            return "refused_existing_grant"

        added_grant = not existing
        had_name_grant = name in await asyncio.to_thread(trusted_app_names)
        if added_grant:
            await asyncio.to_thread(_grant, name, repository)
            if await asyncio.to_thread(trusted_app_repository, name) != repository:
                # config.local.json owns a trust key, so the base write is inert.
                await asyncio.to_thread(_revoke, name, drop_name=not had_name_grant)
                logger.error(
                    "Default install %r: the trust grant did not take effect "
                    "(config.local.json overrides it); skipping",
                    name,
                )
                return "grant_ineffective"

        try:
            result = await _install_transaction(name)
        except Exception:
            logger.exception("Default install %r raised", name)
            result = {"ok": False}
        if not result.get("ok") or result.get("needsClientInstall"):
            if added_grant:
                await asyncio.to_thread(_revoke, name, drop_name=not had_name_grant)
            _audit(name, "failed", "install_failed")
            return "install_failed"

        await asyncio.to_thread(_mark_applied, name)
        _audit(name, "completed", "installed_and_trusted")
        return "installed"


async def reconcile_default_installs() -> dict[str, str]:
    """Install every declared default app not yet handled. Returns name -> outcome.

    Never raises except ``PlatformCompositionError``: it runs as a background
    task after boot, and a failed install is retried on the next boot.
    """
    rows = await asyncio.to_thread(_declared_rows)
    if not rows:
        return {}
    try:
        applied = await asyncio.to_thread(_applied_names)
    except PlatformCompositionError:
        raise
    except Exception:  # noqa: BLE001 - doing nothing is the safe answer
        logger.warning("could not read %s; skipping default installs", _APPLIED_KEY)
        return {}
    outcomes: dict[str, str] = {}
    for name, registry in rows:
        if name in applied:
            continue
        try:
            outcomes[name] = await _install_one(name, registry)
        except PlatformCompositionError:
            raise
        except Exception:  # noqa: BLE001 - one app must not stop the others
            logger.exception("Default install %r failed", name)
            outcomes[name] = "error"
        logger.info("Default install %r: %s", name, outcomes[name])
    return outcomes
