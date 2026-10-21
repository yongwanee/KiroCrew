"""Context rules: a secret found by the field it sits in or the key ID beside it.

Two rules live here, both ranked after the fixed patterns of
:mod:`kiro_crew.security.redaction_patterns`:

* **Labelled values.** A value after a secret field name (``password =``,
  ``"SecretAccessKey":``, ``Authorization: Bearer``) is a Secret. Only the VALUE
  is replaced; the label stays, so structured output still parses and a reader
  sees which field went. Labels match case-insensitively and accept any of the
  usual word separators (see ``credential_patterns``).
* **Key-ID pairing.** An AWS access key ID is an Identifier and stays visible,
  but an unlabelled 40-character secret-shaped value next to one is the secret
  half of the pair, so that value is a Secret.

Each function returns spans against its input; the redactor merges them with the
other passes' spans.

:mod:`kiro_crew.security.redaction` is the import path callers use.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from typing import NamedTuple

from kiro_crew import credential_values
from kiro_crew.credential_patterns import (
    AUTHORIZATION_LABEL,
    AUTHORIZATION_VALUE,
    AWS_KEY_ID,
    AWS_KEY_ID_REDACTION,
    AWS_LABEL_WORDS,
    AWS_SECRET_LABEL,
    AWS_SESSION_LABEL,
    BARE_SIGNATURE_LABEL,
    GENERIC_LABEL_WORDS,
    GENERIC_SECRET_LABEL,
    LABEL_SEPARATOR,
    LABEL_VALUE_OR_QUOTED,
    RULE_TIERS,
    SIGNING_LABEL,
    TIER_SECRET,
)

from .redaction_normalise import normalised_view
from .secret_catalog import catalog_keyword_start, is_identifier_value

#: Every rule id this module writes into a span.
RULE_IDS = (
    "authorization_header",
    "aws_secret_access_key",
    "aws_session_token",
    "secret_label",
    "aws_key_pair",
    "request_signature",
)


#: The rules whose finding blocks a request: Secret tier, except a generic
#: labelled value (it redacts output; its label is too weak to refuse on).
BLOCKING_RULE_IDS = frozenset(
    rule for rule in RULE_IDS if RULE_TIERS[rule] == TIER_SECRET and rule != "secret_label"
)


class LabelSpan(NamedTuple):
    """One value to redact: its span, the rule that found it and the label kept."""

    start: int
    end: int
    rule: str
    label: str


#: A secret label, its separator and its value. The label has no left boundary:
#: a label glued to the text before it (``AWS_SECRET_ACCESS_KEY=``) is still one.
_LABELLED_RE = re.compile(
    rf"(?P<label>(?:(?P<aws_secret>{AWS_SECRET_LABEL})|(?P<aws_session>{AWS_SESSION_LABEL})"
    rf"|{GENERIC_SECRET_LABEL}){LABEL_SEPARATOR})(?P<value>{LABEL_VALUE_OR_QUOTED})"
)

#: The AWS labels with no separator at all (``aws configure set
#: aws_secret_access_key <key>``, ``--aws-secret-access-key <key>``, ``secret
#: access key is <key>``) or with the value in brackets (``key: <value>``). The
#: label alone is weak evidence here, so the value must have the secret's own
#: shape: 40 base64 characters for the key, 100 or more for a session token.
_AWS_SHAPED_RE = re.compile(
    rf"(?P<label>(?:{AWS_SECRET_LABEL}|(?P<session>{AWS_SESSION_LABEL}))"
    r"""["'>]?\s{0,8}(?:(?i:is|was)\s|[:=])?\s{0,8}["'<{(\[]?)"""
    r"(?P<value>(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40}(?![A-Za-z0-9+/=])"
    r"|(?<![A-Za-z0-9+/=])[A-Za-z0-9+/=]{100,})"
)

#: A field whose NAME is a secret label and whose value sits in a sibling field:
#: ``{"name": "AWS_SECRET_ACCESS_KEY", "value": "..."}`` (container and task
#: environments) and its YAML form.
_NAME_VALUE_RE = re.compile(
    r"""(?i:name)["']?\s{0,8}[:=]\s{0,8}["']?"""
    rf"(?P<name>[A-Za-z0-9_.-]{{0,40}}(?:{AWS_SECRET_LABEL}|{AWS_SESSION_LABEL}|{GENERIC_SECRET_LABEL}))"
    r"""["']?\s{0,8},?\s{0,16}(?:-\s{1,8})?"""
    r"""(?P<label>["']?(?i:value)["']?\s{0,8}[:=]\s{0,8}["']?)"""
    rf"(?P<value>{LABEL_VALUE_OR_QUOTED})"
)

#: The labels whose value is a credential whatever its shape: the AWS secret
#: access key and session token, as plain patterns for a scan that reads only
#: ``get_credential_patterns()``.
FIXED_LABEL_RE = re.compile(
    rf"(?:{AWS_SECRET_LABEL}|{AWS_SESSION_LABEL}){LABEL_SEPARATOR}(?![$%{{<*])"
    r"""[^\s"'`,;&{}()<>\[\]\\]{8,}"""
)

_AUTHORIZATION_RE = re.compile(rf"(?P<label>{AUTHORIZATION_LABEL})(?P<value>{AUTHORIZATION_VALUE})")

#: A signing value behind its label, in any serialisation (``"X-Amz-Signature":
#: "..."``, ``X-Amz-Security-Token: ...``), and a bare ``Signature`` field.
_SIGNING_RE = re.compile(
    rf"(?P<label>(?:(?P<named>{SIGNING_LABEL})|{BARE_SIGNATURE_LABEL})"
    r"""["']?\s{0,8}[:=]\s{0,8}["']?)"""
    rf"(?P<value>{LABEL_VALUE_OR_QUOTED})"
)

#: Words that, before ``_token``, name a token that is not a credential: a page
#: cursor, a form's anti-forgery nonce, a count.
_NOT_A_SECRET_TOKEN = frozenset(
    {"next", "page", "pagination", "continuation", "cursor", "csrf", "xsrf", "sync", "resume"}
    | {"max", "num", "total", "count", "the", "a", "end", "start", "stop", "sort", "search"}
)


def _names_no_secret(label: str) -> bool:
    """A ``*_token`` label whose word before it names a cursor or a nonce."""
    words = [w for w in re.split(r"[^a-z0-9]+", label.lower()) if w]
    # The text before a label can end mid-word; only the last two words count.
    return len(words) >= 2 and words[-1] == "token" and words[-2] in _NOT_A_SECRET_TOKEN


def _in_arn(text: str, pos: int) -> bool:
    """A label word right after a ``:`` of an ARN (``arn:...:secret:name``) is a
    resource type; after ``$env:`` or any other colon it is still a label."""
    if pos == 0 or text[pos - 1] != ":":
        return False
    token = text[max(0, pos - 256) : pos].split()
    return bool(token) and "arn:" in token[-1].lower()


#: The longest quoted value read through to its closing quote.
QUOTED_MAX = credential_values.QUOTED_MAX


def _labelled_value(text: str, m: re.Match[str]) -> tuple[str, int, str]:
    """``(value, end, quote)``: a quoted literal runs to its closing quote
    (:func:`credential_values.value_extent`), never shorter than the unquoted run."""
    value, end, start = m["value"], m.end("value"), m.start("value")
    quote = m["label"][-1] if m["label"][-1] in "\"'" else ""
    if quote:
        close = credential_values.value_extent(text, start, quote)
        if close > end:
            value, end = text[start:close], close
    return value, end, quote


def _value_is_secret(text: str, value: str, end: int, quote: str, *, aws: bool = False) -> bool:
    """:func:`credential_values.labelled_value_is_secret` for a value ending at *end*."""
    next_char = text[end] if end < len(text) else ""
    return credential_values.labelled_value_is_secret(
        value, quoted=bool(quote), next_char=next_char, aws=aws
    )


def fixed_label_patterns() -> list[re.Pattern[str]]:
    """The AWS label and ``Authorization`` patterns, for scans that only search."""
    return [FIXED_LABEL_RE, _AUTHORIZATION_RE]


def label_spans(text: str) -> list[LabelSpan]:
    """Every labelled secret value in *text*, sorted by start and disjoint."""
    found: list[LabelSpan] = []
    for m in _SIGNING_RE.finditer(text):
        value, end, quote = _labelled_value(text, m)
        if not value or credential_values.is_tag(value):
            continue
        # A named signing value goes whatever its shape; a bare ``Signature``
        # is judged like any labelled value (``<p>Signature: Jane</p>`` stays).
        if m["named"] is None and not _value_is_secret(text, value, end, quote):
            continue
        rule = "aws_session_token" if "token" in m["label"].lower() else "request_signature"
        found.append(LabelSpan(m.start("value"), end, rule, m["label"]))
    for m in _AUTHORIZATION_RE.finditer(text):
        found.append(
            LabelSpan(m.start("value"), m.end("value"), "authorization_header", m["label"])
        )
    for m in _LABELLED_RE.finditer(text):
        value, end, quote = _labelled_value(text, m)
        aws = m["aws_secret"] is not None or m["aws_session"] is not None
        if not _value_is_secret(text, value, end, quote, aws=aws):
            continue
        if aws:
            rule = "aws_secret_access_key" if m["aws_secret"] is not None else "aws_session_token"
        elif (
            # Inside an ARN (``...:secret:name``) the word is a resource type.
            not _in_arn(text, m.start())
            and not _names_no_secret(text[max(0, m.start() - 40) : m.end("label")])
        ):
            rule = "secret_label"
        else:
            continue
        found.append(LabelSpan(m.start("value"), end, rule, m["label"]))
    for m in _AWS_SHAPED_RE.finditer(text):
        if _secret_shaped(m["value"]) or (m["session"] is not None and len(m["value"]) >= 100):
            rule = "aws_session_token" if m["session"] is not None else "aws_secret_access_key"
            found.append(LabelSpan(m.start("value"), m.end("value"), rule, m["label"]))
    for m in _NAME_VALUE_RE.finditer(text):
        value, end, quote = _labelled_value(text, m)
        if _value_is_secret(text, value, end, quote):
            found.append(LabelSpan(m.start("value"), end, "secret_label", m["label"]))
    # A label that sits inside an earlier match's value is part of that value,
    # not a label: judge overlap from where each label starts.
    found.sort(key=lambda span: span.start - len(span.label))
    disjoint: list[LabelSpan] = []
    for span in found:
        if disjoint and span.start - len(span.label) < disjoint[-1].end:
            continue
        disjoint.append(span)
    return disjoint


#: A keyword every context rule's match starts at: a label, a key ID prefix or
#: a URI scheme.
_CONTEXT_HINT_RE = re.compile(
    rf"{AWS_SECRET_LABEL}|{AWS_SESSION_LABEL}|{GENERIC_SECRET_LABEL}|{SIGNING_LABEL}"
    r"|(?i:signature|authorization|name)|AKIA|ASIA|ABIA|ACCA|://"
)


def has_context_hint(text: str) -> bool:
    """Whether *text* holds a keyword some context rule's match starts at."""
    return _CONTEXT_HINT_RE.search(text) is not None


# ── URI passwords with a slash ──
# The fixed URI-userinfo pattern stops a password at ``/`` so it never runs past
# the authority into the path. A password may still carry an unencoded ``/`` (a
# cloud secret key used as a database password does), so this rule reads a
# password that holds one, up to the first ``@`` that is followed by a host.
_URI_SLASH_PASSWORD_RE = re.compile(
    r"(?<![A-Za-z0-9+.-])(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|https?|ftps?)"
    r"://[^\s:/@]{0,128}:(?P<value>[^\s/@]{0,256}/[^\s@]{0,256}?)@"
    r"(?=[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*(?::[0-9]{1,5})?(?:[/?#\s\"'>]|\Z))"
)


def uri_password_spans(text: str) -> list[LabelSpan]:
    """Passwords holding a ``/`` in ``scheme://user:password@host`` URIs."""
    if "://" not in text:
        return []
    return [
        LabelSpan(m.start("value"), m.end("value"), "url_userinfo", "")
        for m in _URI_SLASH_PASSWORD_RE.finditer(text)
    ]


# ── Key-ID pairing ──
#: Any AWS key ID a secret can be paired with. Only an upper-case letter or a
#: digit before it is part of a longer token; a lower-case word glued in front
#: (``key<ID>``) still leaves it a key ID.
_KEY_ID_RE = re.compile(rf"(?<![A-Z0-9])(?:{AWS_KEY_ID}|{AWS_KEY_ID_REDACTION})(?![A-Za-z0-9])")

#: A run of the base64 alphabet a secret access key can sit in.
_PAIR_RUN_RE = re.compile(r"[A-Za-z0-9+/=]{40,}")

#: How far from a key ID its secret may sit: the width of a CSV row, a JSON
#: object or an ``export`` pair of lines, in characters, on either side.
_PAIR_REACH = 256

#: The length of a secret access key.
_SECRET_LEN = 40


def _secret_shaped(value: str) -> bool:
    """A 40-character value that can be a secret key: mixed case or symbols, not hex."""
    if is_identifier_value(value):
        return False
    # The secret key's alphabet is base64; a digit is common but not required.
    return any(c.islower() for c in value) and any(c.isupper() for c in value)


def _secret_key_piece(run: str) -> tuple[int, int] | None:
    """Where a base64 run holds a 40-character secret-shaped key, as offsets in
    *run*: the whole run, or a 40-character piece between its edges and ``/``,
    ``+``, ``=``. ``None`` when it holds none."""
    # A key may itself start or end with ``/`` or ``+``: judge the run as written
    # before reading the separators off its edges.
    if len(run) == _SECRET_LEN and _secret_shaped(run):
        return 0, _SECRET_LEN
    lead = len(run) - len(run.lstrip("/+="))
    core = run.strip("/+=")
    if len(core) == _SECRET_LEN:
        return (lead, lead + _SECRET_LEN) if _secret_shaped(core) else None
    cuts = [0, *(i + 1 for i, c in enumerate(core) if c in "/+="), len(core)]
    edges = set(cuts) | {c - 1 for c in cuts if c > 0}
    for a in cuts:
        piece = core[a : a + _SECRET_LEN]
        if len(piece) == _SECRET_LEN and a + _SECRET_LEN in edges and _secret_shaped(piece):
            return lead + a, lead + a + _SECRET_LEN
    for b in cuts:
        a = b - _SECRET_LEN
        if a >= 0 and (a in edges or a + 1 in edges) and _secret_shaped(core[a:b]):
            return lead + a, lead + b
    return None


def _holds_secret_key(run: str) -> bool:
    """Whether a base64 run holds a secret-shaped key (:func:`_secret_key_piece`)."""
    return _secret_key_piece(run) is not None


def paired_secret_spans(text: str, units: list[tuple[int, int]] | None = None) -> list[LabelSpan]:
    """Secret keys within reach of an AWS access key ID, in either order and
    behind any delimiter.

    The key IDs are blanked out of a working copy, so a run that touches one ends
    there; every base64 run within :data:`_PAIR_REACH` of a key ID that holds a
    secret-shaped 40-character key has that key redacted. The key ID itself is never
    in a span: it is an Identifier. *units*, when given, receives each pair as
    one span, key ID and secret.
    """
    if not any(prefix in text for prefix in _KEY_ID_PREFIXES):
        return []
    keys = [m.span() for m in _KEY_ID_RE.finditer(text)]
    if not keys:
        return []
    work = list(text)
    for start, end in keys:
        work[start:end] = " " * (end - start)
    blanked = "".join(work)
    key_starts = [start for start, _ in keys]
    found: list[LabelSpan] = []
    for m in _PAIR_RUN_RE.finditer(blanked):
        # The nearest key ID on either side, found by bisection.
        i = bisect_left(key_starts, m.end())
        near = [keys[j] for j in (i - 1, i) if 0 <= j < len(keys)]
        near = [k for k in near if m.start() < k[1] + _PAIR_REACH and k[0] - _PAIR_REACH < m.end()]
        piece = _secret_key_piece(m.group()) if near else None
        if piece is None:
            continue
        # Only the key itself goes: the label or path text glued to it stays.
        start, end = m.start() + piece[0], m.start() + piece[1]
        found.append(LabelSpan(start, end, "aws_key_pair", ""))
        if units is not None:
            key = near[0]
            units.append((min(key[0], start), max(key[1], end)))
    return found


# ── Stream holdback ──
# The stream redactor emits text in pieces, and a context rule needs its whole
# match in one batch call. Every context rule declares where its match starts
# (its trigger) and how far it can reach; the stream holds from the earliest
# trigger whose match may still be arriving, on the raw text and on its
# normalised view. One table, so a new rule adds a row, not a predicate.

#: How far a key ID's pairing reaches: a 40-character key within the reach.
_PAIR_HOLD_REACH = _PAIR_REACH + _SECRET_LEN + 1

#: How far back a quoted value's label may sit: the label and separator, the
#: longest quoted value the batch rule reads, its closing quote and what follows.
QUOTED_HOLD_REACH = 96 + QUOTED_MAX + 64

#: How far a vendor-catalog rule reaches past its keyword.
_CATALOG_HOLD_REACH = 200

#: How far a ``name`` field reaches to its sibling ``value``.
_NAME_HOLD_REACH = 160

#: The longest tail the hold reads.
_HOLD_TAIL = max(_PAIR_HOLD_REACH, QUOTED_HOLD_REACH)

_KEY_ID_PREFIXES = ("AKIA", "ASIA", "ABIA", "ACCA")

#: Every label the batch rules read, at the start of its label and separator:
#: a separator is ``=``, ``:``, ``=>`` and the like, ``is``/``was``, or blanks.
_LABEL_TRIGGER_RE = re.compile(
    rf"(?:{AWS_SECRET_LABEL}|{AWS_SESSION_LABEL}|{GENERIC_SECRET_LABEL}|{SIGNING_LABEL}"
    rf"|{BARE_SIGNATURE_LABEL}|(?i:(?:proxy-)?authorization))"
    r"""(?P<sep>["'*_\\>]{0,6}\s{0,8}(?:(?:=>|:=|[:=>\uff1a\uff1d]|(?i:is|was)\s)\s{0,8})?"""
    r"""(?:(?i:bearer|basic|token)\s{1,8})?[*_\\<{(\[]{0,3}(?P<quote>["']?))"""
)


#: A multi-word label still arriving at the buffer end (``api ke``, ``secret
#: acc``), built from the same word table as the labels themselves.
def _prefixes(word: str, tail: str = "") -> str:
    """A regex for any prefix of *word*, empty included; *tail* may follow it whole."""
    pattern = tail
    for char in reversed(word):
        pattern = f"(?:{re.escape(char)}{pattern})?"
    return pattern


def _partial_label(words: tuple[str, ...]) -> str:
    """A regex for a multi-word label cut anywhere after its first word."""
    tail = ""
    for word in reversed(words[1:]):
        tail = f"(?:[ _.-]?{_prefixes(word, tail)})?"
    return re.escape(words[0]) + tail


_PARTIAL_LABEL_RE = re.compile(
    "(?<![A-Za-z])(?i:"
    + "|".join(
        _partial_label(words)
        for words in (*AWS_LABEL_WORDS, *GENERIC_LABEL_WORDS)
        if len(words) > 1
    )
    + r")\Z"
)
_NAME_TRIGGER_RE = re.compile(r"""(?i:name)["']?\s{0,8}[:=]""")
_UNQUOTED_RUN_RE = re.compile(r"""[^\s"'`,;&{}()<>\[\]\\]*""")
#: A base64 block wrapped over lines, as PEM, MIME and ``base64`` write it.
_B64_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=")
_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/=]*")
_LINE_BREAK_RE = re.compile(r"\r?\n|\\n")


def _wrapped_block_start(buf: str, lo: int) -> int | None:
    """Where a base64 block wrapped over lines (by newlines or literal ``\\n``)
    starts, when it reaches the end of *buf*; one pass over the tail's lines."""
    spans: list[tuple[int, int]] = []
    pos = lo
    for brk in _LINE_BREAK_RE.finditer(buf, lo):
        spans.append((pos, brk.start()))
        pos = brk.end()
    spans.append((pos, len(buf)))
    last_start, last_end = spans[-1]
    if len(spans) < 2 or _B64_RUN_RE.fullmatch(buf, last_start, last_end) is None:
        return None
    start = None
    for line_start, line_end in reversed(spans[:-1]):
        if line_end - line_start >= 16 and _B64_RUN_RE.fullmatch(buf, line_start, line_end):
            start = line_start
            continue
        # The block's first line may share its line with prose before it.
        run = line_end
        while run > line_start and buf[run - 1] in _B64_CHARS:
            run -= 1
        if line_end - run >= 16:
            start = run
        break
    return start


def _label_still_arriving(buf: str, m: re.Match[str]) -> bool:
    """Whether label match *m*'s value may still be arriving: no value yet, or a
    value that runs to the buffer end (a quoted one, to its unclosed quote)."""
    start = m.end()
    if start >= len(buf):
        return True
    if m["quote"]:
        end = credential_values.value_extent(buf, start, m["quote"])
        if end >= len(buf):
            return True
        # Just closed (or past the bound) with only a short non-blank run after
        # it: the stream's own cut would otherwise land inside the value.
        rest = buf[end + (1 if buf[end] in (m["quote"], "\n") else 0) :]
        return len(rest) <= 64 and not any(c.isspace() for c in rest)
    run = _UNQUOTED_RUN_RE.match(buf, start)
    return run is not None and run.end() >= len(buf)


def stream_hold_start(buf: str) -> int | None:
    """:func:`_hold_start` on the buffer and on its normalised view, the earlier.

    The batch pass also reads labels through escapes and terminal codes
    (``{\\"password\\": ...}``), so the hold looks through them too and maps the
    view's position back to the buffer.
    """
    hold = _hold_start(buf)
    lo = max(0, len(buf) - 2 * _HOLD_TAIL)
    view = normalised_view(buf[lo:])
    seen = _hold_start(view.text) if view is not None else None
    if view is not None and seen is not None and seen < len(view.text):
        start = lo + view.starts[seen]
        hold = start if hold is None else min(hold, start)
    return hold


def open_quoted_start(buf: str) -> int | None:
    """Where a labelled quoted value still open at the buffer's end starts its
    label, looking back :data:`QUOTED_HOLD_REACH`; ``None`` when there is none.

    The stream holds from here until the closing quote, past its usual 512
    floor up to that reach, so the value is redacted beside its label.
    """
    for m in _LABEL_TRIGGER_RE.finditer(buf, max(0, len(buf) - QUOTED_HOLD_REACH)):
        if m["quote"] and _label_still_arriving(buf, m):
            return m.start()
    return None


def _hold_start(buf: str) -> int | None:
    """Where the stream must hold from so every context rule sees its whole match.

    The earliest trigger whose reach has not fully arrived: a label whose value
    may still be arriving (:func:`_label_still_arriving`, at most
    :data:`QUOTED_HOLD_REACH`), a ``name`` field, a key ID or a base64 run that
    holds a key (either may be the first of a pair), a wrapped base64 block
    reaching the end, and a vendor-catalog keyword. ``None`` when nothing needs
    holding. Reads only the buffer's tail, so it costs the same however long
    the buffer is.
    """
    lo = max(0, len(buf) - _HOLD_TAIL)
    starts: list[int] = []
    for m in _LABEL_TRIGGER_RE.finditer(buf, max(0, len(buf) - QUOTED_HOLD_REACH)):
        if _label_still_arriving(buf, m):
            starts.append(m.start())
            break
    partial = _PARTIAL_LABEL_RE.search(buf, max(0, len(buf) - 24))
    if partial is not None:
        starts.append(partial.start())
    for m in _NAME_TRIGGER_RE.finditer(buf, max(0, len(buf) - _NAME_HOLD_REACH)):
        starts.append(m.start())
        break
    if any(prefix in buf[lo:] for prefix in _KEY_ID_PREFIXES):
        for key in _KEY_ID_RE.finditer(buf, lo):
            if len(buf) - key.end() < _PAIR_HOLD_REACH:
                starts.append(key.start())
                break
    for run in _PAIR_RUN_RE.finditer(buf, lo):
        if len(buf) - run.end() < _PAIR_HOLD_REACH and _holds_secret_key(run.group()):
            starts.append(run.start())
            break
    wrapped = _wrapped_block_start(buf, lo)
    if wrapped is not None:
        starts.append(wrapped)
    keyword = catalog_keyword_start(buf, max(0, len(buf) - _CATALOG_HOLD_REACH))
    if keyword is not None:
        starts.append(keyword)
    return min(starts) if starts else None
