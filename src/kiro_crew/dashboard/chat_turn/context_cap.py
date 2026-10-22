"""The context cap: goal conductors (``docs/request-for-change/rfc-conductor-context-cap.md``)
and dispatched workers (``docs/request-for-change/rfc-worker-context-cap.md``).

A goal conductor's or a bound worker's KAS chat over its marks is trimmed at a
dashboard turn's start, before the turn claims its session: the KAS conversation ends
through ``discard_conversation(replay=True)``, and the session the turn then starts is
seeded from what the chat already keeps. A conductor's seed is a trim note, the
session-ledger snapshot and a longer text tail of the transcript; a worker's is a trim
note, its work item (brief and latest report), the files it edited and a text tail
sized in tokens. No model call is spent, and the transcript on disk gains only the
notice row.
"""

from __future__ import annotations

import asyncio
import json
import math
import time
import uuid
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from kiro_crew.dashboard.chat_runner import (
        DashboardState,
        KiroCrewConfig,
        _broadcast_expired_oauth_banners,
        _ChatSlot,
        append_and_surface,
        logger,
        subagents_attached_async,
    )

#: Where a trim lands, in tokens. A cold request there takes about as long as a warm
#: one at 400K.
CONTEXT_CAP_LOW_TOKENS = 150_000
#: Rule A: a session over this at a turn's start is trimmed, warm cache or not.
CONTEXT_CAP_HIGH_TOKENS = 400_000
#: Rule B: a session over this whose previous turn ended a cache life ago is trimmed.
CONTEXT_CAP_IDLE_TOKENS = CONTEXT_CAP_LOW_TOKENS + 50_000
#: The prompt-cache life Rule B measures the gap against, in seconds.
CONTEXT_CAP_CACHE_SECS = 300.0
#: A session a trim started is not trimmed again until its reading has grown this far
#: past its first one, so a trim that lands high cannot repeat on every cold turn.
CONTEXT_CAP_DAMPING_TOKENS = 50_000
#: The trim's replay budget in chars: the room LOW leaves after a fresh conductor
#: session's ~55K-token start and ~5K for the note, the snapshot and the message, at
#: 3 chars per token. Every other cold start keeps ``_REPLAY_BUDGET_CHARS``.
CONTEXT_CAP_TAIL_CHARS = 270_000
#: Trims remembered at once, one per capped chat key; past it the oldest goes.
_CONTEXT_CAP_MAX_TRIMS = 256

#: The agent a dispatched worker runs; it is capped only while its session is bound to
#: a work item (``work_ledger.read_binding``), which is what its seed is built from.
WORKER_CAP_AGENT = "kirocrew-worker"
#: Worker Rule B: over this, once the cache has expired, a worker is trimmed. A worker
#: is never trimmed under it on a warm cache (rfc-worker-context-cap section 5.2).
WORKER_CAP_IDLE_TOKENS = 200_000
#: Worker safety line (its Rule A): over this a worker is trimmed warm or cold, before
#: a long turn can reach KAS's own summarization at 80% of a 1M window.
WORKER_CAP_HIGH_TOKENS = 600_000
#: A worker trim's text tail, in estimated tokens (``model_route.prompt_tokens``): the
#: room 150K leaves after a fresh worker session's ~46K and ~4K for the seed's head.
WORKER_CAP_TAIL_TOKENS = 100_000
#: Edited files a worker's seed lists, newest first, paths only.
WORKER_CAP_MAX_EDITED_FILES = 30
#: Transcript rows read back for the edited-file and skill-file lists.
_CONTEXT_CAP_SCAN_ROWS = 4_000
#: Skill and instruction files a seed lists, newest first, paths only. A trim drops
#: their bodies with the rest of the tool output, so the note asks for a re-read.
CONTEXT_CAP_MAX_SKILL_FILES = 10
#: File names that are skill bodies or agent instruction files.
_INSTRUCTION_FILE_NAMES = frozenset({"SKILL.md", "AGENTS.md", "CLAUDE.md"})
#: Heads the seed's skill-file list, in both seeds.
CONTEXT_CAP_SKILL_FILES_HEADING = (
    "[Skill and instruction files this chat read before the trim, newest first: "
    "re-read them before you act on them]"
)

#: Opens a trimmed worker session's replay.
WORKER_CAP_TRIM_NOTE = (
    "[Context trimmed: this chat moved to a new session at the start of this turn, to "
    "keep its context small. Tool calls, their output, your reasoning and older "
    "messages are not in this context; your work item, your latest work_report, the "
    "skill files you read, the files you edited and the newest messages follow. "
    "Everything else is in this chat's transcript: search_chat_history searches it and "
    "get_chat_session reads it ({transcript}). Before acting, first re-read the skill "
    "and instruction files listed below, then re-read the files you are editing from "
    "your worktree, and re-read your pull request's state.]"
)

#: Opens a trimmed session's replay: what the model needs to know about the trim.
CONTEXT_CAP_TRIM_NOTE = (
    "[Context trimmed: this chat moved to a new session at the start of this turn, to "
    "keep its context small. Its newest messages follow as text. Tool calls, their "
    "output and older messages are not in this context. They are in this chat's "
    "transcript: search_chat_history searches it and get_chat_session reads it. "
    "First re-read any skill and instruction files listed below.]"
)

#: The notice row a trim leaves in the transcript, for the person. It names only the
#: reading that fired: where the new session lands is known after its first request.
#: The restart notices' memory sentence follows it.
CONTEXT_CAP_NOTICE_TEXT = (
    "♻️ Context reached {reached}K tokens, so the session was restarted on a shorter context."
)


@dataclass
class _CapTrim:
    """What the cap remembers about the session one of its trims started."""

    #: The next cold start's replay is the trim's seed. Spent only once a provider is
    #: known to hold it, so a cold start that fails before the provider keeps its
    #: prompt, or whose session dies first, is rebuilt from the same seed.
    seed_pending: bool = True
    #: A replay was built from the seed.
    seeded: bool = False
    #: The session the trim started and its reading, both taken at the first turn
    #: start that reads it. The damping guard counts from that reading.
    sid: str = ""
    first_tokens: int = 0
    #: Whose marks and seed: ``"conductor"`` or ``"worker"``.
    kind: str = "conductor"
    #: ``meta.trim`` on this trim's own notice row. The seed's file scan passes over
    #: that row (it may be flushed before the seed is built) and stops at any other.
    notice_id: str = field(default_factory=lambda: uuid.uuid4().hex)


#: Session key -> the trim that started the session now on that key.
_CONTEXT_CAP_TRIMS: dict[str, _CapTrim] = {}


async def _cap_conductor_context(
    state: DashboardState,
    slot: _ChatSlot,
    session_key: str,
    cfg: KiroCrewConfig | None,
    *,
    is_slash: bool,
) -> str:
    """Trim *slot*'s conductor or bound-worker KAS chat over its marks, before the claim.

    Runs at a dashboard turn's start, beside the pending-reset consume. Returns
    ``"trimmed"`` or the hold that stopped the trim (RFC section 3.4); every hold
    leaves the session as it is, and the next turn start checks again. Never raises:
    a failure costs the trim, never the turn.
    """
    try:
        return await _context_cap_trim(state, slot, session_key, cfg, is_slash=is_slash)
    except Exception:
        logger.warning(
            "Context cap: check failed for slot %s; the turn keeps its session",
            slot.key,
            exc_info=True,
        )
        return "error"


async def _context_cap_trim(
    state: DashboardState,
    slot: _ChatSlot,
    session_key: str,
    cfg: KiroCrewConfig | None,
    *,
    is_slash: bool,
) -> str:
    from kiro_crew.autonudge_selfarm import WAKE_RESET_AGENTS
    from kiro_crew.dashboard.session_directive_apply import _slot_has_pending_interaction

    _settle_context_cap_seed(state, session_key)
    # An unreadable config reads as off: a trim is never the fallback.
    if cfg is None or not cfg.session.context_cap:
        return "cap_off"
    agent = str(slot.agent or "")
    if agent in WAKE_RESET_AGENTS:
        kind = "conductor"
    elif agent == WORKER_CAP_AGENT:
        kind = "worker"
    else:
        return "out_of_scope"
    if is_slash:
        return "slash_command"
    provider = state.sessions.get_provider(session_key)
    if provider is None:
        return "no_session"
    backend = getattr(provider, "harness_managed_compaction_backend", None)
    if not (isinstance(backend, str) and backend):
        return "out_of_scope"
    if kind == "worker" and await _context_cap_worker_binding(session_key) is None:
        # An unbound worker chat has no item to seed from (rfc-worker-context-cap 5.1).
        return "out_of_scope"
    tokens = _context_cap_reading(provider)
    if tokens is None:
        return "unknown_reading"
    floor = _context_cap_damping_floor(state, session_key, tokens)
    rule = _context_cap_rule(tokens, _context_cap_idle_secs(state, session_key), kind=kind)
    if rule is None:
        return "below_marks"
    if floor is not None and tokens < floor:
        hold = "damped"
    elif slot._pending_discard_conversation_key:
        # The queued reset lands at this turn's end and drops more than a trim.
        hold = "reset_queued"
    elif _slot_has_pending_interaction(state, slot):
        # The answer would reach a session without the question in its context.
        hold = "interaction_pending"
    elif await subagents_attached_async(state, slot, session_key, "context_cap"):
        # The teardown releases the runtime the children run on.
        hold = "subagents_attached"
    elif not await _context_cap_discard(state, slot, session_key):
        # Another turn holds the session; the refusal changed nothing.
        hold = "busy"
    else:
        hold = ""
    if hold:
        logger.info(
            "Context cap: slot %s at %dK of context (rule %s) left on its session: %s",
            slot.key,
            tokens // 1000,
            rule,
            hold,
        )
        return hold
    trim = _remember_context_cap_trim(session_key, kind=kind)
    _append_context_cap_notice(state, slot, tokens, trim.notice_id)
    logger.info(
        "Context cap: slot %s at %dK of context (rule %s) trimmed; this turn starts a new session",
        slot.key,
        tokens // 1000,
        rule,
    )
    return "trimmed"


def _context_cap_rule(
    tokens: int, idle_secs: float | None, *, kind: str = "conductor"
) -> str | None:
    """The rule that trims a session at *tokens* whose previous turn ended *idle_secs* ago.

    Rule A: over HIGH (a worker's safety line). Rule B: over the Rule B line once the
    cache life has passed, when the next request writes a new cache either way.
    ``None``: neither holds. *kind* picks the marks: the conductor's or a worker's.
    """
    if kind == "worker":
        high, idle_line = WORKER_CAP_HIGH_TOKENS, WORKER_CAP_IDLE_TOKENS
    else:
        high, idle_line = CONTEXT_CAP_HIGH_TOKENS, CONTEXT_CAP_IDLE_TOKENS
    if tokens > high:
        return "A"
    if idle_secs is not None and idle_secs >= CONTEXT_CAP_CACHE_SECS:
        if tokens > idle_line:
            return "B"
    return None


async def _context_cap_worker_binding(session_key: str) -> tuple[str, str] | None:
    """The ``(conductor key, item id)`` a worker session is bound to, or ``None``.

    The same lookup ``work_brief`` resolves, under the ledger's spelling of the key.
    """
    from kiro_crew import work_ledger
    from kiro_crew.session_ledger import ledger_key

    return await asyncio.to_thread(work_ledger.read_binding, ledger_key(session_key))


def _context_cap_reading(provider: Any) -> int | None:
    """The session's last confirmed context reading in tokens, or ``None`` when unknown.

    The reading is the previous turn's last request: the percentage times the window.
    A reading the provider calls unknown, a zero one and one with no window never trim.
    """
    from kiro_crew.context import window_for_provider_client  # circular: context -> chat
    from kiro_crew.session_parts.provider_probes import _context_pct_is_unknown

    if _context_pct_is_unknown(provider):
        return None
    pct = provider.context_usage_pct()
    if isinstance(pct, bool) or not isinstance(pct, (int, float)) or not math.isfinite(pct):
        return None
    window = window_for_provider_client(provider)
    if pct <= 0 or not window:
        return None
    return int(pct * window / 100)


def _context_cap_idle_secs(state: DashboardState, session_key: str) -> float | None:
    """Seconds since the session's previous turn ended, or ``None`` when unknown.

    Read off ``_Session.last_used``: ``SessionAllocationService.release`` stamps it at a
    turn's end, and this check runs before the next turn acquires, so it holds that end.
    Every other writer stamps a later moment, which can only read the cache warmer.
    """
    record = getattr(state.sessions, "_sessions", {}).get(session_key)
    last_used = getattr(record, "last_used", None)
    if isinstance(last_used, bool) or not isinstance(last_used, (int, float)):
        return None
    return time.monotonic() - last_used


def _context_cap_damping_floor(state: DashboardState, session_key: str, tokens: int) -> int | None:
    """The reading a session a trim started must reach before another trim, or ``None``.

    The first turn start that reads the session after its trim names it (its sid) and
    takes its reading. A session that replaced it since is not damped.
    """
    trim = _CONTEXT_CAP_TRIMS.get(session_key)
    if trim is None:
        return None
    sid = state.sessions.mapped_sid(session_key)
    if not isinstance(sid, str) or not sid:
        return None
    if not trim.sid:
        trim.sid, trim.first_tokens = sid, tokens
    elif trim.sid != sid:
        _CONTEXT_CAP_TRIMS.pop(session_key, None)
        return None
    return trim.first_tokens + CONTEXT_CAP_DAMPING_TOKENS


async def _context_cap_discard(state: DashboardState, slot: _ChatSlot, session_key: str) -> bool:
    """End the slot's KAS conversation with replay kept on; False when a turn holds it.

    ``skip_if_busy`` refuses under the same session lock that pops the session, so a
    turn that starts between the checks above and the teardown is never cut.
    """
    try:
        discarded = await state.sessions.discard_conversation(
            session_key, replay=True, skip_if_busy=True
        )
    except Exception:
        # A teardown that raised leaves a session this slot cannot vouch for.
        slot.forget_session_model_state()
        raise
    if not discarded:
        return False
    # The discarded conversation advertised the model list and the MCP report.
    slot.forget_session_model_state()
    if slot.clear_mcp_report():
        state.broadcast_ws("mcp_report_update", {"slot": slot.key, "mcp_report": None})
    _broadcast_expired_oauth_banners(state, slot)
    return True


def _remember_context_cap_trim(session_key: str, *, kind: str = "conductor") -> _CapTrim:
    _CONTEXT_CAP_TRIMS.pop(session_key, None)
    while len(_CONTEXT_CAP_TRIMS) >= _CONTEXT_CAP_MAX_TRIMS:
        _CONTEXT_CAP_TRIMS.pop(next(iter(_CONTEXT_CAP_TRIMS)))
    trim = _CONTEXT_CAP_TRIMS[session_key] = _CapTrim(kind=kind)
    return trim


def _append_context_cap_notice(
    state: DashboardState, slot: _ChatSlot, tokens: int, notice_id: str = ""
) -> None:
    """One notice row per trim, drawn by the compaction card; the replay skips it."""
    from kiro_crew.context_assembly.replay import CONTEXT_CAP_NOTICE
    from kiro_crew.dashboard.state import _RESTART_MEMORY_TAIL

    text = CONTEXT_CAP_NOTICE_TEXT.format(reached=round(tokens / 1000))
    try:
        append_and_surface(
            state,
            slot,
            "assistant",
            f"{text} {_RESTART_MEMORY_TAIL}",
            "msg msg-a",
            meta={"kind": "compaction", "notice": CONTEXT_CAP_NOTICE, "trim": notice_id},
        )
    except Exception:
        logger.debug("Context cap: notice row failed for slot %s", slot.key, exc_info=True)


def _spend_context_cap_seed(session_key: str) -> None:
    """The turn that built a trim's seed delivered its first-turn history: spend the seed.

    Called where ``_run_chat``'s ``finally`` settles the first-turn history debt, the
    one point that knows the provider kept the prompt, before anything between turns
    can end the session.
    """
    trim = _CONTEXT_CAP_TRIMS.get(session_key)
    if trim is not None and trim.seeded:
        trim.seed_pending = False


def _settle_context_cap_seed(state: DashboardState, session_key: str) -> None:
    """Spend a trim's seed once a live session is seen holding it: built, and not owed.

    A session that is gone proves nothing either way (it may have died before its
    provider kept the prompt), so the seed waits for the next cold start.
    """
    trim = _CONTEXT_CAP_TRIMS.get(session_key)
    if (
        trim is not None
        and trim.seed_pending
        and trim.seeded
        and state.sessions.get_provider(session_key) is not None
        and state.sessions.first_turn_history_owed_pending(session_key) is not True
    ):
        trim.seed_pending = False


def _take_context_cap_seed(session_key: str) -> bool:
    """Whether the replay this cold start builds is a trim's seed."""
    trim = _CONTEXT_CAP_TRIMS.get(session_key)
    if trim is None or not trim.seed_pending:
        return False
    trim.seeded = True
    return True


def _drop_context_cap_seed(session_key: str) -> None:
    """A cold start a reset told to forget spends the trim's seed without building it."""
    trim = _CONTEXT_CAP_TRIMS.get(session_key)
    if trim is not None:
        trim.seed_pending = False


def _context_cap_seed_budget(session_key: str) -> dict[str, int]:
    """``build_session_replay``'s budget for the seed of the trim on *session_key*.

    A conductor's tail is ``CONTEXT_CAP_TAIL_CHARS`` chars; a worker's is
    ``WORKER_CAP_TAIL_TOKENS`` estimated tokens.
    """
    trim = _CONTEXT_CAP_TRIMS.get(session_key)
    if trim is not None and trim.kind == "worker":
        return {"budget_tokens": WORKER_CAP_TAIL_TOKENS}
    return {"budget_chars": CONTEXT_CAP_TAIL_CHARS}


async def _context_cap_seed_head(
    session_key: str, conversation_log: Any = None, state: DashboardState | None = None
) -> str:
    """What opens a trimmed session's replay, before its text tail.

    A conductor's: the trim note, the session-ledger snapshot and the skill files it
    read. A worker's: its trim note, its work item, the skill files it read and the
    files it edited (:func:`_worker_cap_seed_head`).
    """
    trim = _CONTEXT_CAP_TRIMS.get(session_key)
    if trim is not None and trim.kind == "worker":
        return await _worker_cap_seed_head(session_key, conversation_log, state)
    return await _conductor_cap_seed_head(session_key, conversation_log)


async def _conductor_cap_seed_head(session_key: str, conversation_log: Any = None) -> str:
    """The trim note, the session-ledger snapshot and the skill files a conductor read.

    The snapshot is the block a patrol wake already carries (``compose_nudge_body``),
    read off the loop; a failed read costs the snapshot, never the seed.
    """
    from kiro_crew.session_ledger import ledger_key, render_snapshot

    try:
        snapshot = await asyncio.to_thread(render_snapshot, ledger_key(session_key))
    except Exception:
        logger.debug("Context cap: ledger snapshot failed for %s", session_key, exc_info=True)
        snapshot = ""
    _edited, skills = await _context_cap_file_lists(conversation_log, session_key)
    parts = [CONTEXT_CAP_TRIM_NOTE]
    if snapshot:
        parts.append(snapshot)
    if skills:
        parts.append(_file_block(CONTEXT_CAP_SKILL_FILES_HEADING, skills))
    return "\n\n".join(parts) + "\n\n"


async def _worker_cap_seed_head(
    session_key: str, conversation_log: Any, state: DashboardState | None = None
) -> str:
    """The trim note, the work item, the skill files read and the files edited.

    Each part that fails to read costs that part, never the seed. The item block is
    private dispatch data, so it is read the way ``work_brief`` reads it
    (:func:`_worker_cap_item`) and passes the ledger's entry gate after the last
    await (:func:`_worker_cap_admit_item`).
    """
    try:
        note = await asyncio.to_thread(_worker_cap_note, session_key)
    except Exception:
        logger.debug("Context cap: transcript path failed for %s", session_key, exc_info=True)
        note = WORKER_CAP_TRIM_NOTE.format(transcript="its transcript file")
    try:
        item = await _worker_cap_item(session_key)
    except Exception:
        logger.debug("Context cap: worker item read failed for %s", session_key, exc_info=True)
        item = ""
    edited, skills = await _context_cap_file_lists(conversation_log, session_key)
    if item and not _worker_cap_admit_item(state, session_key):
        item = ""
    parts = [note]
    if item:
        parts.append(item)
    if skills:
        parts.append(_file_block(CONTEXT_CAP_SKILL_FILES_HEADING, skills))
    if edited:
        parts.append(_file_block("[Files you edited in this chat, newest first]", edited))
    return "\n\n".join(parts) + "\n\n"


def _worker_cap_admit_item(state: DashboardState | None, session_key: str) -> bool:
    """Whether the work item may enter this session's seed, recording its audience.

    The one gate every ledger route passes (``caller_admission``): refused when the
    session's replies reach a channel audience. On admission it records the audience
    the session was admitted under (``record_audience_admission``), so a mirror
    gained before the reply publishes still withholds it. Fails closed: a missing
    item costs a ``work_brief`` call; a published one cannot be taken back.
    """
    if state is None:
        return False
    from kiro_crew.dashboard import session_control
    from kiro_crew.dashboard.handlers.work_ledger_caller import caller_admission

    try:
        why, slot, admission = caller_admission(state, session_key)
        if why:
            return False
        if admission is not None:
            session_control.record_audience_admission(slot, admission)
    except Exception:
        logger.debug("Context cap: channel check failed for %s", session_key, exc_info=True)
        return False
    return True


def _file_block(heading: str, paths: list[str]) -> str:
    return heading + "\n" + "\n".join(f"- {p}" for p in paths)


def _worker_cap_note(session_key: str) -> str:
    """The worker's trim note, naming its transcript file."""
    from kiro_crew.history_files import _sessions_dir, transcript_stem

    transcript = str(_sessions_dir() / f"{transcript_stem(session_key)}.jsonl")
    return WORKER_CAP_TRIM_NOTE.format(transcript=transcript)


async def _worker_cap_item(session_key: str) -> str:
    """The worker's work-item block, read the way ``work_brief`` reads it.

    The brief (title, acceptance, the conductor's decision) and the item's latest
    ``work_report`` (status, summary, artifacts, pull request), read through the
    worker's own binding, under the board's lock and never while its cache is
    flagged dirty (``_refuse_if_dirty``). ``""`` when the binding or the item is gone
    or the cache is dirty.
    """
    from kiro_crew import work_ledger
    from kiro_crew.dashboard.handlers.work_ledger_recording import _board_lock

    binding = await _context_cap_worker_binding(session_key)
    if binding is None:
        return ""
    async with _board_lock(binding[0]):
        if await asyncio.to_thread(work_ledger.cache_dirty, binding[0]) is not None:
            return ""
        item = await asyncio.to_thread(work_ledger.read_work_item, *binding)
    if item is None:
        return ""
    lines = [
        "[Your work item: the brief work_brief returns, and your latest work_report]",
        f"title: {item.title}",
        f"acceptance: {json.dumps(item.acceptance, ensure_ascii=False, sort_keys=True)}",
        f"conductor's decision: {item.decision or '(none)'}",
        f"latest report: {item.status or '(none yet)'}"
        + (f" ({item.reason})" if item.reason else ""),
    ]
    if item.summary:
        lines.append(f"summary: {item.summary}")
    for key in sorted(item.artifacts or {}):
        lines.append(f"artifact {key}: {item.artifacts[key]}")
    if item.pr is not None:
        lines.append(f"pr: {item.pr}")
    return "\n".join(lines)


async def _context_cap_file_lists(
    conversation_log: Any, session_key: str
) -> tuple[list[str], list[str]]:
    """``(files edited, skill files read)`` since the last trim; ``([], [])`` on failure."""
    if conversation_log is None:
        return [], []
    try:
        return await asyncio.to_thread(_context_cap_scan_files, conversation_log, session_key)
    except Exception:
        logger.debug("Context cap: file list read failed for %s", session_key, exc_info=True)
        return [], []


def _context_cap_scan_files(conversation_log: Any, session_key: str) -> tuple[list[str], list[str]]:
    """Paths the chat's tool rows name since its last trim, newest first, deduped.

    Edited: every file an edit row names, at most ``WORKER_CAP_MAX_EDITED_FILES``.
    Skills: every skill or instruction file a read row names
    (:func:`_is_skill_or_instruction_file`), at most ``CONTEXT_CAP_MAX_SKILL_FILES``.
    The scan passes over the current trim's own notice row, which the flush may have
    persisted before this seed is built, and stops at any other notice row: what an
    earlier session read is not in the session that trim started, and its own seed
    listed it then.
    """
    from kiro_crew.context_assembly.replay import is_context_cap_notice

    trim = _CONTEXT_CAP_TRIMS.get(session_key)
    current = trim.notice_id if trim is not None else None
    rows = conversation_log.read_messages_chained_tail(session_key, _CONTEXT_CAP_SCAN_ROWS)
    edited: list[str] = []
    skills: list[str] = []
    for row in reversed(rows):
        if is_context_cap_notice(row):
            if current and (row.get("meta") or {}).get("trim") == current:
                continue
            break
        meta = row.get("meta")
        if row.get("role") != "tool" or not isinstance(meta, dict):
            continue
        path = _tool_row_path(meta.get("input"))
        if not path:
            continue
        kind = meta.get("kind")
        if kind == "edit" and path not in edited and len(edited) < WORKER_CAP_MAX_EDITED_FILES:
            edited.append(path)
        elif (
            kind == "read"
            and _is_skill_or_instruction_file(path)
            and path not in skills
            and len(skills) < CONTEXT_CAP_MAX_SKILL_FILES
        ):
            skills.append(path)
    return edited, skills


def _is_skill_or_instruction_file(path: str) -> bool:
    """A skill body, an agent instruction file, or a steering file."""
    norm = path.replace("\\", "/")
    name = norm.rsplit("/", 1)[-1]
    return name in _INSTRUCTION_FILE_NAMES or "/.kiro/steering/" in norm


def _tool_row_path(tool_input: Any) -> str:
    """The file a tool row's input names: a ``--- file://`` diff or a ``path`` arg."""
    if not isinstance(tool_input, str):
        return ""
    head = tool_input.split("\n", 1)[0]
    if head.startswith("--- file://"):
        return head[len("--- file://") :].strip()
    try:
        args = json.loads(tool_input)
    except ValueError:
        return ""
    path = args.get("path") if isinstance(args, dict) else None
    return path.strip() if isinstance(path, str) else ""
