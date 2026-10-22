"""claude and goose below their first steering release are refused at the handshake.

The card's ``mid_turn_steer`` line reads membership, so it says yes for every claude
and goose. That is only true from the release whose steer Crew speaks: below it, the
session is refused with the installed version, the minimum and the upgrade command,
the way pi is refused below its floor.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from kiro_crew.acp.client import AcpClient
from kiro_crew.acp.client_turn_control import GOOSE_STEER_MIN_VERSION, steer_version_issue
from kiro_crew.acp.transport_errors import AcpError
from kiro_crew.agent_sdk import backends as sdk_backends
from kiro_crew.agent_sdk.backend_cards import card_payload

CLAUDE = sdk_backends.ACP_BACKEND_CLAUDE
GOOSE = sdk_backends.ACP_BACKEND_GOOSE
FRAMES = Path(__file__).resolve().parent / "fixtures" / "acp_frames"


@pytest.mark.parametrize(
    ("backend", "version", "minimum", "fix"),
    [
        (CLAUDE, "0.64.9", "0.65.0", "npm i -g @agentclientprotocol/claude-agent-acp"),
        (CLAUDE, "0.61.0", "0.65.0", "npm i -g @agentclientprotocol/claude-agent-acp"),
        (GOOSE, "1.37.0", "1.38.0", "download_cli.sh | bash"),
        # A prerelease of the floor sorts below it.
        (CLAUDE, "0.65.0-rc.1", "0.65.0", "npm i -g @agentclientprotocol/claude-agent-acp"),
        (GOOSE, "1.38.0-beta", "1.38.0", "download_cli.sh | bash"),
    ],
)
def test_below_the_floor_names_installed_minimum_and_fix(backend, version, minimum, fix):
    issue = steer_version_issue(backend, version)
    assert version in issue
    assert f"{minimum} or newer" in issue
    assert fix in issue


@pytest.mark.parametrize(
    ("backend", "version"),
    [
        (CLAUDE, "0.65.0"),
        (CLAUDE, "0.93.0"),
        (CLAUDE, "0.65.0+build.7"),
        (CLAUDE, "0.66.0-rc.1"),
        (GOOSE, "1.38.0"),
        (GOOSE, "1.54.0"),
    ],
)
def test_at_or_above_the_floor_is_not_refused(backend, version):
    assert steer_version_issue(backend, version) == ""


@pytest.mark.parametrize("version", ["", "unknown", "dev", "0.1.0000000000", "0.1.0.4"])
def test_an_unknown_version_is_not_refused(version):
    """As for pi: only a version known to be old is refused."""
    assert steer_version_issue(CLAUDE, version) == ""
    assert steer_version_issue(GOOSE, version) == ""


@pytest.mark.parametrize("backend", sorted(set(sdk_backends.ACP_BACKENDS_KNOWN) - {CLAUDE, GOOSE}))
def test_other_harnesses_have_no_steer_floor(backend):
    assert steer_version_issue(backend, "0.0.1") == ""


def test_no_committed_handshake_is_refused():
    """Every live claude and goose capture is at or above its floor."""
    seen = 0
    for backend in (CLAUDE, GOOSE):
        for path in sorted((FRAMES / backend).glob("*.jsonl")):
            for line in path.read_text(encoding="utf-8").splitlines():
                frame = json.loads(line) if line.strip() else {}
                info = (
                    (frame.get("result") or {}).get("agentInfo")
                    if isinstance(frame, dict)
                    else None
                )
                if isinstance(info, dict) and info.get("version"):
                    seen += 1
                    assert steer_version_issue(backend, info["version"]) == "", path
    assert seen


def test_goose_floor_is_one_release_above_the_last_without_steer():
    assert GOOSE_STEER_MIN_VERSION == (1, 38, 0)


@pytest.mark.parametrize("backend", [CLAUDE, GOOSE])
def test_the_card_is_unchanged(backend):
    lines = {line["id"]: line for line in card_payload(backend)["capabilities"]}
    assert lines["mid_turn_steer"]["available"] is True


def _handshake(tmp_path, backend, version):
    client = AcpClient(work_dir=tmp_path, acp_backend=backend)

    async def _send(method, params=None):
        return 1

    async def _wait(req_id, timeout=None):
        return {"protocolVersion": 1, "agentInfo": {"version": version}}

    client._send_request = _send  # type: ignore[method-assign]
    client._wait_for_response = _wait  # type: ignore[method-assign]
    return asyncio.run(client._initialize_session())


@pytest.mark.parametrize(("backend", "version"), [(CLAUDE, "0.64.0"), (GOOSE, "1.37.0")])
def test_the_handshake_refuses_below_the_floor(tmp_path, backend, version):
    with pytest.raises(AcpError, match="then start a new chat"):
        _handshake(tmp_path, backend, version)


@pytest.mark.parametrize(("backend", "version"), [(CLAUDE, "0.65.0"), (GOOSE, "1.38.0")])
def test_the_handshake_passes_the_floor(tmp_path, backend, version):
    """At the floor the handshake goes on to its next step, whatever that answers."""
    try:
        _handshake(tmp_path, backend, version)
    except Exception as exc:  # noqa: BLE001 -- the stub cannot finish a real session
        assert "then start a new chat" not in str(exc)
