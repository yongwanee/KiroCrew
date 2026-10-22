"""The worker context cap (``docs/request-for-change/rfc-worker-context-cap.md``).

Section 8 of the RFC asks, each failing first: a bound worker on KAS over 200K after
300 s is trimmed and its next prompt carries the note, the brief, the report, the
edited files and the tail; the same worker on a warm cache is not; over 600K it is,
warm or cold; an unbound ``kirocrew-worker`` chat and a normal chat are untouched; a
goal conductor keeps its 150/400 marks and its seed; each hold leaves the session in
place; the tail stops at its token budget, not a char budget; the off switch turns it
off. The check runs through ``chat_runner._cap_conductor_context`` on a real slot and
state, and through one whole dashboard turn (``turn_harness.run_turn``) for the call
site; the seed through ``chat_runner._session_replay_history`` and a whole first turn.

Invariant: a worker turn either runs on its old session untouched or starts a new one
whose replay is the worker seed, and only a bound worker on KAS is ever trimmed.
"""

from __future__ import annotations

import dataclasses
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from chat_runner_coverage_helpers import _slot, _state
from context_composition_contract_helpers import (  # noqa: F401 -- the fixture is requested by name
    rig_fixture,
)
from test_conductor_context_cap import KEY as CONDUCTOR_KEY
from test_conductor_context_cap import _approval_pending, _Debt, _Provider, _question_pending
from test_conductor_context_cap import _Sessions as _ConductorSessions
from test_conductor_context_cap import _subagents_attached
from turn_harness import SlotSpec, TurnScript, run_turn

from kiro_crew import work_ledger
from kiro_crew.acp.types import EVENT_COMPLETE, EVENT_TEXT_CHUNK, STOP_REASON_END_TURN, AcpEvent
from kiro_crew.context import build_session_replay
from kiro_crew.dashboard import chat_runner
from kiro_crew.work_ledger_records import WorkItem

KEY = "dashboard:chat-77"
WORKER = "kirocrew-worker"
CONDUCTOR_SLOT = "member-kirocrew-conductor"
ITEM_ID = "it_1178dda6"
NOTICE = "context_cap"


@pytest.fixture(autouse=True)
def _forget_trims():
    trims = getattr(chat_runner, "_CONTEXT_CAP_TRIMS", {})
    trims.clear()
    yield
    trims.clear()


def _item() -> WorkItem:
    return WorkItem(
        item_id=ITEM_ID,
        title="Ship the worker cap",
        acceptance={"kind": "pr_checks", "pr": "TBD", "repo": "kirodotdev/KiroCrew"},
        decision="Build it locally first.",
        status="progress",
        summary="Tests written; build green.",
        artifacts={"branch": "feat/worker-context-cap", "worktree": "/wt/cap"},
        pr=23039,
    )


@pytest.fixture
def bound(monkeypatch) -> dict[str, Any]:
    """Every worker key in these tests is bound to one item, read through the ledger."""
    reads: dict[str, Any] = {"bindings": [], "items": []}

    def _binding(key: str, **_kw) -> tuple[str, str] | None:
        reads["bindings"].append(key)
        return (
            (CONDUCTOR_SLOT, ITEM_ID) if key in reads.get("bound", {"chat-77", "chat-1"}) else None
        )

    def _read_item(slot_key: str, item_id: str) -> WorkItem | None:
        reads["items"].append((slot_key, item_id))
        return _item()

    monkeypatch.setattr(work_ledger, "read_binding", _binding)
    monkeypatch.setattr(work_ledger, "read_work_item", _read_item)
    monkeypatch.setattr(work_ledger, "cache_dirty", lambda _slot: reads.get("dirty"))
    return reads


class _Sessions(_ConductorSessions):
    """The conductor tests' one-live-session manager, answering on the worker's key."""

    def set_idle(self, idle_secs: float) -> None:
        import time

        self._sessions[KEY] = SimpleNamespace(last_used=time.monotonic() - idle_secs)

    def get_provider(self, key: str) -> _Provider | None:
        return self.provider if key == KEY else None


def _cfg(on: bool = True) -> Any:
    return SimpleNamespace(session=SimpleNamespace(context_cap=on))


def _worker(tmp_path, sessions: _Sessions) -> tuple[Any, Any]:
    state, slot = _state(tmp_path), _slot("chat-77")
    state.sessions = sessions
    slot.agent = WORKER
    return state, slot


async def _check(state, slot, *, cfg: Any = None, key: str = KEY) -> str:
    return await chat_runner._cap_conductor_context(
        state, slot, key, _cfg() if cfg is None else cfg, is_slash=False
    )


def _notices(slot) -> list[dict]:
    return [m for m in slot.messages if (m.get("meta") or {}).get("notice") == NOTICE]


# ── the marks ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("tokens", "idle", "rule"),
    [
        (600_001, 0.0, "A"),
        (600_000, 0.0, None),
        (450_000, 0.0, None),
        (450_000, None, None),
        (200_001, 300.0, "B"),
        (200_000, 300.0, None),
        (599_000, 299.9, None),
    ],
)
def test_the_worker_marks_fire_only_past_their_lines(tokens, idle, rule):
    """Rule B past 200K once the cache has expired; the safety line past 600K."""
    assert chat_runner._context_cap_rule(tokens, idle, kind="worker") == rule


def test_the_worker_marks_are_named_constants():
    assert chat_runner.WORKER_CAP_IDLE_TOKENS == 200_000
    assert chat_runner.WORKER_CAP_HIGH_TOKENS == 600_000
    assert chat_runner.WORKER_CAP_TAIL_TOKENS == 100_000
    assert chat_runner.CONTEXT_CAP_CACHE_SECS == 300.0
    assert chat_runner.CONTEXT_CAP_DAMPING_TOKENS == 50_000


@pytest.mark.asyncio
async def test_a_bound_worker_over_200k_after_300s_is_trimmed(tmp_path, bound):
    sessions = _Sessions(_Provider(250_000), idle_secs=3_600.0)
    state, slot = _worker(tmp_path, sessions)

    assert await _check(state, slot) == "trimmed"

    assert sessions.discards == [(KEY, True, True)]
    assert bound["bindings"] == ["chat-77"]
    assert len(_notices(slot)) == 1
    assert chat_runner._CONTEXT_CAP_TRIMS[KEY].kind == "worker"


@pytest.mark.parametrize("tokens", [250_000, 450_000, 600_000])
@pytest.mark.asyncio
async def test_a_bound_worker_on_a_warm_cache_under_600k_is_left_alone(tmp_path, bound, tokens):
    """450K warm trims a conductor (its Rule A) but not a worker: the cache stays whole."""
    sessions = _Sessions(_Provider(tokens), idle_secs=0.0)
    state, slot = _worker(tmp_path, sessions)

    assert await _check(state, slot) == "below_marks"
    assert sessions.discards == [] and _notices(slot) == []


@pytest.mark.parametrize("idle", [0.0, 3_600.0], ids=["warm", "cold"])
@pytest.mark.asyncio
async def test_a_bound_worker_over_600k_is_trimmed_warm_or_cold(tmp_path, bound, idle):
    sessions = _Sessions(_Provider(650_000), idle_secs=idle)
    state, slot = _worker(tmp_path, sessions)

    assert await _check(state, slot) == "trimmed"
    assert sessions.discards == [(KEY, True, True)]


@pytest.mark.asyncio
async def test_an_unbound_worker_chat_is_untouched(tmp_path, bound):
    bound["bound"] = set()
    sessions = _Sessions(_Provider(900_000), idle_secs=3_600.0)
    state, slot = _worker(tmp_path, sessions)

    assert await _check(state, slot) == "out_of_scope"
    assert sessions.discards == [] and _notices(slot) == []


@pytest.mark.asyncio
async def test_a_normal_chat_is_untouched_and_reads_no_binding(tmp_path, bound):
    sessions = _Sessions(_Provider(900_000), idle_secs=3_600.0)
    state, slot = _worker(tmp_path, sessions)
    slot.agent = "kirocrew"

    assert await _check(state, slot) == "out_of_scope"
    assert sessions.discards == [] and bound["bindings"] == []


@pytest.mark.asyncio
async def test_a_goal_conductor_keeps_its_150_400_marks(tmp_path, bound):
    """A conductor at 450K on a warm cache is still trimmed (its 400K Rule A)."""
    sessions = _ConductorSessions(_Provider(450_000), idle_secs=0.0)
    state, slot = _state(tmp_path), _slot(CONDUCTOR_SLOT)
    state.sessions = sessions
    slot.agent = "kirocrew-conductor"

    assert await _check(state, slot, key=CONDUCTOR_KEY) == "trimmed"
    assert chat_runner._CONTEXT_CAP_TRIMS[CONDUCTOR_KEY].kind == "conductor"
    assert chat_runner._context_cap_seed_budget(CONDUCTOR_KEY) == {"budget_chars": 270_000}
    assert bound["bindings"] == []


@pytest.mark.asyncio
async def test_a_trimmed_worker_is_damped_until_it_grows_50k(tmp_path, bound):
    sessions = _Sessions(_Provider(650_000))
    state, slot = _worker(tmp_path, sessions)
    assert await _check(state, slot) == "trimmed"
    sessions.start_session(210_000, sid="sid-2", idle_secs=3_600.0)
    assert await _check(state, slot) == "damped"

    sessions.start_session(260_000, sid="sid-2", idle_secs=3_600.0)
    assert await _check(state, slot) == "trimmed"


# ── the holds ───────────────────────────────────────────────────────────────


def _reset_queued(sessions, state, slot) -> None:
    slot._pending_discard_conversation_key = KEY


def _not_kas(sessions, state, slot) -> None:
    sessions.provider.harness_managed_compaction_backend = None


def _unknown(sessions, state, slot) -> None:
    sessions.provider = _Provider(650_000, unknown=True)


def _no_session(sessions, state, slot) -> None:
    sessions.provider = None


def _busy(sessions, state, slot) -> None:
    sessions.busy = True


@pytest.mark.parametrize(
    ("arrange", "hold"),
    [
        (_unknown, "unknown_reading"),
        (_no_session, "no_session"),
        (_not_kas, "out_of_scope"),
        (_reset_queued, "reset_queued"),
        (_question_pending, "interaction_pending"),
        (_approval_pending, "interaction_pending"),
        (_subagents_attached, "subagents_attached"),
        (_busy, "busy"),
    ],
    ids=lambda value: getattr(value, "__name__", value),
)
@pytest.mark.asyncio
async def test_a_hold_leaves_the_worker_session_in_place(tmp_path, bound, arrange, hold):
    sessions = _Sessions(_Provider(650_000), idle_secs=3_600.0)
    state, slot = _worker(tmp_path, sessions)
    arrange(sessions, state, slot)

    assert await _check(state, slot) == hold

    assert sessions.provider is None or sessions.provider.pct > 0
    assert _notices(slot) == []
    assert chat_runner._take_context_cap_seed(KEY) is False


@pytest.mark.parametrize("cfg", [_cfg(on=False), None], ids=["off", "unreadable"])
@pytest.mark.asyncio
async def test_the_off_switch_leaves_a_worker_alone(tmp_path, bound, cfg):
    sessions = _Sessions(_Provider(900_000), idle_secs=3_600.0)
    state, slot = _worker(tmp_path, sessions)

    result = await chat_runner._cap_conductor_context(state, slot, KEY, cfg, is_slash=False)

    assert result == "cap_off"
    assert sessions.discards == [] and bound["bindings"] == []


# ── the seed ────────────────────────────────────────────────────────────────


def _edit_row(state, path: str, *, diff: bool = True) -> None:
    tool_input = (
        f"--- file://{path}\n+++ file://{path}\n@@ -1 +1 @@\n-a\n+b"
        if diff
        else json.dumps({"path": path})
    )
    state.conversation_log.append(
        KEY, "tool", "🔧 Replace in File", extra_meta={"kind": "edit", "input": tool_input}
    )


async def _replay(state, slot) -> str:
    return await chat_runner._session_replay_history(
        state,
        SimpleNamespace(conversation_log=state.conversation_log),
        slot,
        _Provider(60_000),
        KEY,
        _context_is_new=True,
        _provider_has_history=False,
        _current_replay_message=None,
    )


@pytest.mark.asyncio
async def test_the_trimmed_worker_replays_its_note_item_edited_files_and_tail(tmp_path, bound):
    sessions = _Sessions(_Provider(650_000))
    state, slot = _worker(tmp_path, sessions)
    state.conversation_log.append(KEY, "user", "Fix the cap, one PR.")
    _edit_row(state, "/wt/cap/src/a.py")
    state.conversation_log.append(KEY, "assistant", "Edited a.py.")
    _edit_row(state, "/wt/cap/src/b.py", diff=False)
    _edit_row(state, "/wt/cap/src/a.py")
    state.conversation_log.append(KEY, "assistant", "Tests pass.")
    assert await _check(state, slot) == "trimmed"

    seed = await _replay(state, slot)

    assert seed.startswith("[Context trimmed:")
    assert "dashboard_chat-77.jsonl" in seed
    assert "search_chat_history" in seed and "get_chat_session" in seed
    assert "re-read the files you are editing from your" in seed
    for fact in (
        "title: Ship the worker cap",
        '"pr": "TBD"',
        "conductor's decision: Build it locally first.",
        "latest report: progress",
        "summary: Tests written; build green.",
        "artifact branch: feat/worker-context-cap",
        "artifact worktree: /wt/cap",
        "pr: 23039",
    ):
        assert fact in seed, fact
    files = seed.split("[Files you edited in this chat, newest first]\n", 1)[1].split("\n\n", 1)[0]
    assert files.splitlines() == ["- /wt/cap/src/a.py", "- /wt/cap/src/b.py"]
    assert seed.rstrip().endswith("Assistant: Tests pass.")
    assert bound["items"] == [(CONDUCTOR_SLOT, ITEM_ID)]
    assert chat_runner.CONTEXT_CAP_TRIM_NOTE not in seed


@pytest.mark.asyncio
async def test_the_edited_file_list_starts_after_the_last_trim(tmp_path, bound):
    sessions = _Sessions(_Provider(650_000))
    state, slot = _worker(tmp_path, sessions)
    _edit_row(state, "/wt/old.py")
    state.conversation_log.append(
        KEY, "assistant", "♻️ trimmed", extra_meta={"kind": "compaction", "notice": NOTICE}
    )
    _edit_row(state, "/wt/new.py")
    state.conversation_log.append(KEY, "user", "go on")
    assert await _check(state, slot) == "trimmed"

    seed = await _replay(state, slot)

    assert "- /wt/new.py" in seed and "/wt/old.py" not in seed


@pytest.mark.asyncio
async def test_the_file_lists_survive_the_current_trim_notice_being_flushed(tmp_path, bound):
    """The flush can persist this trim's own notice before the seed scans the log."""
    sessions = _Sessions(_Provider(650_000))
    state, slot = _worker(tmp_path, sessions)
    _edit_row(state, "/wt/cap/src/a.py")
    _read_row(state, "/skills/kirocrew-prepare-pr/SKILL.md")
    state.conversation_log.append(KEY, "user", "go on")
    assert await _check(state, slot) == "trimmed"
    (notice,) = _notices(slot)
    state.conversation_log.append(KEY, "assistant", notice["content"], extra_meta=notice["meta"])

    seed = await _replay(state, slot)

    assert "- /wt/cap/src/a.py" in seed
    assert "- /skills/kirocrew-prepare-pr/SKILL.md" in seed


@pytest.mark.asyncio
@pytest.mark.parametrize("gate", ["mirrored", "raises"])
async def test_a_worker_that_reaches_a_channel_gets_no_item_in_its_seed(
    tmp_path, bound, monkeypatch, gate
):
    """The item is what the ledger's entry gate refuses a channel-mirrored session."""
    from kiro_crew.dashboard.handlers import work_ledger_caller

    def _admission(_state, _sk):
        if gate == "raises":
            raise RuntimeError("store unreadable")
        return "the mirror reaches a shared channel", None, None

    sessions = _Sessions(_Provider(650_000))
    state, slot = _worker(tmp_path, sessions)
    _edit_row(state, "/wt/cap/src/a.py")
    state.conversation_log.append(KEY, "user", "hello")
    assert await _check(state, slot) == "trimmed"
    monkeypatch.setattr(work_ledger_caller, "caller_admission", _admission)

    seed = await _replay(state, slot)

    assert seed.startswith("[Context trimmed:")
    assert "Your work item" not in seed and "Ship the worker cap" not in seed
    assert "- /wt/cap/src/a.py" in seed
    assert seed.rstrip().endswith("User: hello")


@pytest.mark.asyncio
async def test_an_admitted_worker_seed_records_the_audience_it_was_admitted_under(
    tmp_path, bound, monkeypatch
):
    """A mirror gained after the seed is built must still withhold the reply."""
    from kiro_crew.dashboard import session_control
    from kiro_crew.dashboard.handlers import work_ledger_caller

    admission = {"containment": "unmirrored"}
    recorded: list[tuple[Any, Any]] = []
    sessions = _Sessions(_Provider(650_000))
    state, slot = _worker(tmp_path, sessions)
    state.conversation_log.append(KEY, "user", "hello")
    assert await _check(state, slot) == "trimmed"
    monkeypatch.setattr(
        work_ledger_caller, "caller_admission", lambda _state, _sk: ("", slot, admission)
    )
    monkeypatch.setattr(
        session_control, "record_audience_admission", lambda s, a: recorded.append((s, a))
    )

    seed = await _replay(state, slot)

    assert "title: Ship the worker cap" in seed
    assert recorded == [(slot, admission)]


@pytest.mark.asyncio
async def test_a_dirty_board_cache_keeps_the_item_out_of_the_seed(tmp_path, bound):
    """``work_brief`` refuses a dirty cache; the seed must not serve it either."""
    sessions = _Sessions(_Provider(650_000))
    state, slot = _worker(tmp_path, sessions)
    state.conversation_log.append(KEY, "user", "hello")
    assert await _check(state, slot) == "trimmed"
    bound["dirty"] = "undo failed"

    seed = await _replay(state, slot)

    assert seed.startswith("[Context trimmed:") and "Your work item" not in seed
    assert bound["items"] == []
    assert seed.rstrip().endswith("User: hello")


@pytest.mark.asyncio
async def test_a_worker_whose_item_is_gone_still_gets_its_note_and_tail(
    tmp_path, bound, monkeypatch
):
    sessions = _Sessions(_Provider(650_000))
    state, slot = _worker(tmp_path, sessions)
    state.conversation_log.append(KEY, "user", "hello")
    assert await _check(state, slot) == "trimmed"
    monkeypatch.setattr(work_ledger, "read_work_item", lambda *_a: None)

    seed = await _replay(state, slot)

    assert seed.startswith("[Context trimmed:") and "Your work item" not in seed
    assert seed.rstrip().endswith("User: hello")


@pytest.mark.parametrize(
    ("text", "max_chars"),
    [("x" * 1_000, 420_000), ("界" * 1_000, 105_000)],
    ids=["ascii", "cjk"],
)
def test_the_worker_tail_stops_at_its_token_budget_not_a_char_budget(tmp_path, text, max_chars):
    """100K tokens hold ~400K ASCII chars but only ~100K CJK chars."""
    state = _state(tmp_path)
    for i in range(600):
        state.conversation_log.append(KEY, "user" if i % 2 == 0 else "assistant", f"{i:04d} {text}")

    tail = build_session_replay(state.conversation_log, KEY, budget_tokens=100_000)

    from kiro_crew.decisions.points.model_route import prompt_tokens

    assert 95_000 < prompt_tokens(tail) <= 100_000
    assert len(tail) <= max_chars
    assert tail.endswith(f"0599 {text}")


# ── the real turn path ──────────────────────────────────────────────────────


def _reply() -> list[AcpEvent]:
    return [
        AcpEvent(kind=EVENT_TEXT_CHUNK, text="the reply"),
        AcpEvent(kind=EVENT_COMPLETE, stop_reason=STOP_REASON_END_TURN),
    ]


#: The discard each harness turn's session manager was given, to read after the turn.
DISCARDS: list[AsyncMock] = []


def _as_worker(ctx) -> None:
    """A worker slot whose previous turn left a live KAS session at 650K.

    The harness answers ``get_provider`` only once the turn has allocated; the
    session a previous turn left is that turn's start reading, so it answers the
    650K meter until then, and the discard the cap asks for succeeds.
    """
    ctx.slot.agent = WORKER
    sessions = ctx.state.sessions
    allocated = sessions.get_provider.side_effect
    left_by_previous_turn = _Provider(650_000)

    def _get_provider(key: str) -> Any:
        return allocated(key) or (left_by_previous_turn if key == "dashboard:chat-1" else None)

    sessions.get_provider.side_effect = _get_provider
    sessions.discard_conversation = AsyncMock(return_value=True)
    DISCARDS.append(sessions.discard_conversation)


@pytest.fixture
def worker_agent(monkeypatch) -> None:
    """``kirocrew-worker`` resolves as an installed template, as on a real install."""
    from kiro_crew.config import loader_agents

    real = loader_agents._materialized_kiro_agent
    monkeypatch.setattr(
        loader_agents,
        "_materialized_kiro_agent",
        lambda name, project_dir=None: WORKER if name == WORKER else real(name, project_dir),
    )


@pytest.mark.asyncio
async def test_a_dashboard_turn_trims_a_bound_worker_over_600k_before_its_claim(
    bound, worker_agent
):
    """A whole dashboard turn: the admission check trims before the turn claims a session."""
    DISCARDS.clear()
    record = await run_turn(
        TurnScript(events=_reply(), setup=_as_worker), slot=SlotSpec(key="chat-1")
    )

    assert record.stop_reason == STOP_REASON_END_TURN
    [discard] = DISCARDS
    discard.assert_awaited_once_with("dashboard:chat-1", replay=True, skip_if_busy=True)
    notices = [r for r in record.history_rows if (r.get("meta") or {}).get("notice") == NOTICE]
    assert len(notices) == 1 and "Context reached 650K tokens" in notices[0]["content"]
    assert bound["bindings"] == ["chat-1"]
    assert chat_runner._CONTEXT_CAP_TRIMS["dashboard:chat-1"].kind == "worker"


@pytest.mark.asyncio
async def test_a_dashboard_turn_leaves_an_unbound_worker_alone(bound, worker_agent):
    bound["bound"] = set()
    DISCARDS.clear()
    record = await run_turn(
        TurnScript(events=_reply(), setup=_as_worker), slot=SlotSpec(key="chat-1")
    )

    assert record.stop_reason == STOP_REASON_END_TURN
    DISCARDS[0].assert_not_awaited()
    assert not [r for r in record.history_rows if (r.get("meta") or {}).get("notice") == NOTICE]


@pytest.mark.asyncio
async def test_a_worker_first_turn_after_a_trim_sends_the_worker_seed(tmp_path, monkeypatch, bound):
    """One whole ``_run_chat`` cold start a worker trim began: its prompt is the seed."""
    from recovery_l1_chat_runner_helpers import _l1_state, _RecordingSlot

    from kiro_crew.dashboard.chat import _run_chat
    from kiro_crew.dashboard.chat_utils import effective_session_key
    from kiro_crew.providers.base import LLMEvent

    state, client = _l1_state(tmp_path)
    client.last_infra_error = None
    debt = _Debt()
    for name in (
        "first_turn_history_owed_pending",
        "mark_first_turn_history_owed",
        "consume_first_turn_history_owed",
        "provider_switch_replay_pending",
        "consume_replay_suppression",
    ):
        setattr(state.sessions, name, getattr(debt, name))
    budgets: list[dict] = []

    def _tail(*_a, **kw):
        budgets.append({k: v for k, v in kw.items() if k.startswith("budget_")})
        return "User: earlier"

    monkeypatch.setattr("kiro_crew.context.build_session_replay", _tail)

    def _stream(*_a, **_kw):
        async def _gen():
            yield LLMEvent(kind=EVENT_TEXT_CHUNK, text="done")
            yield LLMEvent(kind=EVENT_COMPLETE, stop_reason=STOP_REASON_END_TURN)

        return _gen()

    client.stream = MagicMock(side_effect=_stream)
    slot = _RecordingSlot("chat-77")
    key = effective_session_key(slot)
    chat_runner._remember_context_cap_trim(key, kind="worker")
    with patch("kiro_crew.dashboard.chat.sel") as mock_sel:
        mock_sel.return_value = MagicMock()
        await _run_chat(state, slot, "hello")
        if slot.task:
            # flake-ok: awaits the turn task _run_chat itself started, on a scripted client that never blocks
            await slot.task
    prompt = state.context_builder.build_message.call_args_list[0].kwargs["compressed_history"]

    assert prompt.startswith("[Context trimmed:")
    assert "title: Ship the worker cap" in prompt
    assert prompt.endswith("User: earlier")
    assert budgets == [{"budget_tokens": 100_000}]
    assert chat_runner._CONTEXT_CAP_TRIMS[key].seed_pending is False


# ── skill files in both seeds ───────────────────────────────────────────────


def _read_row(state, path: str, key: str = KEY) -> None:
    state.conversation_log.append(
        key,
        "tool",
        "🔧 Read File",
        extra_meta={"kind": "read", "input": json.dumps({"path": path})},
    )


@pytest.mark.asyncio
async def test_the_worker_seed_lists_the_skill_files_it_read_and_says_reread_them(tmp_path, bound):
    sessions = _Sessions(_Provider(650_000))
    state, slot = _worker(tmp_path, sessions)
    _read_row(state, "/home/u/.kiro/crew/skills/kirocrew-dev/kirocrew-prepare-pr/SKILL.md")
    _read_row(state, "/wt/cap/src/a.py")
    _read_row(state, "/wt/cap/AGENTS.md")
    _read_row(state, "/wt/cap/.kiro/steering/style.md")
    _read_row(state, "/home/u/.kiro/crew/skills/kirocrew-dev/kirocrew-prepare-pr/SKILL.md")
    state.conversation_log.append(KEY, "user", "go on")
    assert await _check(state, slot) == "trimmed"

    seed = await _replay(state, slot)

    heading = chat_runner.CONTEXT_CAP_SKILL_FILES_HEADING + "\n"
    listed = seed.split(heading, 1)[1].split("\n\n", 1)[0].splitlines()
    assert listed == [
        "- /home/u/.kiro/crew/skills/kirocrew-dev/kirocrew-prepare-pr/SKILL.md",
        "- /wt/cap/.kiro/steering/style.md",
        "- /wt/cap/AGENTS.md",
    ]
    note = seed.split("\n\n", 1)[0]
    assert "first re-read the skill and instruction files listed below" in note


@pytest.mark.asyncio
async def test_the_skill_file_list_holds_ten_and_starts_after_the_last_trim(tmp_path, bound):
    sessions = _Sessions(_Provider(650_000))
    state, slot = _worker(tmp_path, sessions)
    _read_row(state, "/skills/old/SKILL.md")
    state.conversation_log.append(
        KEY, "assistant", "♻️ trimmed", extra_meta={"kind": "compaction", "notice": NOTICE}
    )
    for i in range(12):
        _read_row(state, f"/skills/s{i:02d}/SKILL.md")
    state.conversation_log.append(KEY, "user", "go on")
    assert await _check(state, slot) == "trimmed"

    seed = await _replay(state, slot)

    listed = seed.split(chat_runner.CONTEXT_CAP_SKILL_FILES_HEADING + "\n", 1)[1]
    listed = listed.split("\n\n", 1)[0].splitlines()
    assert listed == [f"- /skills/s{i:02d}/SKILL.md" for i in range(11, 1, -1)]
    assert "/skills/old/SKILL.md" not in seed


@pytest.mark.asyncio
async def test_the_conductor_seed_lists_the_skill_files_it_read(tmp_path, bound, monkeypatch):
    from kiro_crew import session_ledger

    monkeypatch.setattr(session_ledger, "render_snapshot", lambda key: "goal: ship")
    sessions = _ConductorSessions(_Provider(450_000))
    state, slot = _state(tmp_path), _slot(CONDUCTOR_SLOT)
    state.sessions = sessions
    slot.agent = "kirocrew-conductor"
    _read_row(state, "/skills/goal-conductor/SKILL.md", key=CONDUCTOR_KEY)
    state.conversation_log.append(CONDUCTOR_KEY, "user", "patrol")
    assert await _check(state, slot, key=CONDUCTOR_KEY) == "trimmed"

    seed = await chat_runner._session_replay_history(
        state,
        SimpleNamespace(conversation_log=state.conversation_log),
        slot,
        _Provider(60_000),
        CONDUCTOR_KEY,
        _context_is_new=True,
        _provider_has_history=False,
        _current_replay_message=None,
    )

    assert seed.startswith(chat_runner.CONTEXT_CAP_TRIM_NOTE + "\n\ngoal: ship\n\n")
    assert "First re-read any skill and instruction files listed below" in seed
    assert (
        chat_runner.CONTEXT_CAP_SKILL_FILES_HEADING + "\n- /skills/goal-conductor/SKILL.md" in seed
    )


# ── a trimmed session starts like a brand-new chat ──────────────────────────


async def _first_turn(
    tmp_path, monkeypatch, *, agent: str, trimmed: bool, project
) -> dict[str, Any]:
    """One whole ``_run_chat`` first turn on a fresh session; what it built and claimed."""
    from recovery_l1_chat_runner_helpers import _l1_state, _RecordingSlot

    from kiro_crew.config import loader_agents
    from kiro_crew.dashboard.chat import _run_chat
    from kiro_crew.dashboard.chat_utils import effective_session_key
    from kiro_crew.providers.base import LLMEvent

    real = loader_agents._materialized_kiro_agent
    monkeypatch.setattr(
        loader_agents,
        "_materialized_kiro_agent",
        lambda name, project_dir=None: name if name == agent else real(name, project_dir),
    )
    monkeypatch.setattr("kiro_crew.context.build_session_replay", lambda *a, **k: "User: earlier")
    tmp_path.mkdir(parents=True, exist_ok=True)
    state, client = _l1_state(tmp_path)
    client.last_infra_error = None
    # A direct dashboard chat: no linked channel, as on a dispatched worker.
    state.sessions.get_mirror_link = MagicMock(return_value=None)
    state.sessions.mirror_accepts_inbound = MagicMock(return_value=False)
    debt = _Debt()
    for name in (
        "first_turn_history_owed_pending",
        "mark_first_turn_history_owed",
        "consume_first_turn_history_owed",
        "provider_switch_replay_pending",
        "consume_replay_suppression",
    ):
        setattr(state.sessions, name, getattr(debt, name))

    def _stream(*_a, **_kw):
        async def _gen():
            yield LLMEvent(kind=EVENT_TEXT_CHUNK, text="done")
            yield LLMEvent(kind=EVENT_COMPLETE, stop_reason=STOP_REASON_END_TURN)

        return _gen()

    client.stream = MagicMock(side_effect=_stream)
    slot = _RecordingSlot("chat-77")
    slot.agent = agent
    slot.model = "claude-opus-5.5"
    slot.reasoning_effort = "max"
    slot.project = str(project)
    key = effective_session_key(slot)
    if trimmed:
        chat_runner._remember_context_cap_trim(
            key, kind="worker" if agent == WORKER else "conductor"
        )
    with patch("kiro_crew.dashboard.chat.sel") as mock_sel:
        mock_sel.return_value = MagicMock()
        await _run_chat(state, slot, "hello")
        if slot.task:
            # flake-ok: awaits the turn task _run_chat itself started, on a scripted client that never blocks
            await slot.task
    build = state.context_builder.build_message.call_args_list[0]
    [claim] = state.sessions.get_or_create.await_args_list
    kwargs = dict(build.kwargs)
    # ``selection_revision`` is the session record's publication guard, minted once
    # per record and not a context input (``config/sections_session.py``).
    kwargs["execution_context"] = dataclasses.replace(
        kwargs["execution_context"], selection_revision=""
    )
    return {"build_args": build.args, "build": kwargs, "claim": claim}


@pytest.mark.parametrize("agent", [WORKER, "kirocrew-conductor"])
@pytest.mark.asyncio
async def test_a_trimmed_session_starts_like_a_brand_new_chat(tmp_path, monkeypatch, bound, agent):
    """The first turn after a trim builds and claims exactly what a new chat does.

    The build asks for a NEW session's context (``is_new_session``) with the same
    agent, project, memory store, mode, provider and member inputs, so it carries the
    same startup blocks; only ``compressed_history`` gains the seed head. The claim
    passes the same agent, model, effort, cwd, channel and app inputs to the same
    ``get_or_create``, and the session manager mounts its MCP servers from those.
    """
    project = tmp_path / "project"
    project.mkdir()
    fresh = await _first_turn(
        tmp_path / "fresh", monkeypatch, agent=agent, trimmed=False, project=project
    )
    chat_runner._CONTEXT_CAP_TRIMS.clear()
    trimmed = await _first_turn(
        tmp_path / "trimmed", monkeypatch, agent=agent, trimmed=True, project=project
    )

    assert fresh["build_args"][1] is True and trimmed["build_args"][1] is True
    assert fresh["build_args"] == trimmed["build_args"]
    ignore = {"compressed_history", "context_provider"}
    assert {k: v for k, v in fresh["build"].items() if k not in ignore} == {
        k: v for k, v in trimmed["build"].items() if k not in ignore
    }
    assert fresh["build"]["compressed_history"] == "User: earlier"
    seeded = trimmed["build"]["compressed_history"]
    assert seeded.startswith("[Context trimmed:") and seeded.endswith("User: earlier")
    assert fresh["claim"] == trimmed["claim"]
    claim = trimmed["claim"].kwargs
    assert claim["model"] == "claude-opus-5.5"
    assert claim["reasoning_effort_override"] == "max"
    assert claim["cwd"] == str(project)
    assert claim["agent"] == agent and claim["channel_id"] is None


@pytest.mark.parametrize("agent", [WORKER, "kirocrew-conductor"])
def test_the_real_builder_gives_a_trimmed_session_every_new_chat_block(rig, agent):
    """Through the real ``ContextBuilder``: a new chat's prompt, line for line, plus the seed."""
    rig.seed_memory()
    rig.seed_skill("alpha")
    rig.globs = ["*"]
    kwargs = dict(session_key="dashboard:chat-77", agent=agent, runtime_source="dashboard")
    fresh, _ = rig.builder.build_message("go", True, **kwargs)
    seed = "[Context trimmed: seed head]\n\nUser: earlier ask"
    trimmed, _ = rig.builder.build_message("go", True, compressed_history=seed, **kwargs)

    lines = iter(trimmed.splitlines())
    missing = [line for line in fresh.splitlines() if not any(line == t for t in lines)]
    assert missing == []
    for block in (
        "[CRITICAL RULES -- always follow these]",
        "[CURRENT AGENT]",
        "[Memory tools]",
        "[End of learned corrections]",
        "[End of skills]",
        "[REPLY FORMAT RULES]",
        "[END OF SESSION CONTEXT]",
    ):
        assert block in fresh and block in trimmed, block
    assert "[Context trimmed: seed head]" in trimmed and "User: earlier ask" in trimmed
