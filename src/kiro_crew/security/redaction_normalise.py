"""Input normalisation for the credential redactor.

The same secret reaches the redactor in many spellings: percent-encoded in a
URL, JSON-escaped inside a string, split by a terminal colour code or a
zero-width character. The rules match the plain spelling, so the redactor also
runs them over a NORMALISED VIEW of the text and maps every span it finds there
back to the original characters. Nothing is rewritten in place: the view exists
only to be matched against.

A view is built in up to :data:`_MAX_ROUNDS` rounds, so a value encoded twice
(JSON inside JSON, a percent sign percent-encoded) is still read. Each round
does, left to right:

* ``%XX`` for an ASCII byte becomes that character;
* a JSON escape (``\\"``, ``\\\\``, ``\\/``, ``\\n``, ``\\r``, ``\\t``,
  ``\\uXXXX``) becomes the character it stands for;
* a terminal escape sequence (``ESC [ ... m`` and the other CSI forms), every
  other control character except tab, newline and carriage return, and the
  invisible format characters (zero-width space, joiners, word joiner, byte
  order mark, soft hyphen) are dropped.

:mod:`kiro_crew.security.redaction` is the import path callers use.
"""

from __future__ import annotations

import re
from typing import NamedTuple

#: A round's tokens. Group ``pct``: a percent-encoded ASCII byte. Groups ``uni``
#: and ``esc``: a JSON escape. Group ``drop``: characters that are removed.
_TOKEN_RE = re.compile(
    r"%(?P<pct>[0-7][0-9A-Fa-f])"
    r"|\\(?:u(?P<uni>[0-9A-Fa-f]{4})|(?P<esc>[\"\\/nrtbf]))"
    r"|(?P<drop>\x1b\[[0-9;?]*[ -/]*[@-~]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]"
    r"|[\u00ad\u200b-\u200d\u2060\ufeff])"
)

_JSON_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "b": "\b",
    "f": "\f",
}

#: Rounds of decoding: enough for a value escaped twice plus one more layer.
_MAX_ROUNDS = 3


class View(NamedTuple):
    """A normalised view of a text and, per view character, where it came from.

    View character ``i`` was built from the source characters
    ``starts[i]:ends[i]``. A dropped character has no view character; a span of
    the view therefore maps to the source range from its first character's start
    to its last character's end, which covers anything dropped between them.
    """

    text: str
    starts: list[int]
    ends: list[int]

    def source_span(self, start: int, end: int) -> tuple[int, int]:
        """The source characters a non-empty view span ``[start, end)`` covers."""
        return self.starts[start], self.ends[end - 1]


def _one_round(text: str) -> View | None:
    """One left-to-right decode of *text*, or None when it changes nothing."""
    parts: list[str] = []
    starts: list[int] = []
    ends: list[int] = []
    cursor = 0
    changed = False
    for m in _TOKEN_RE.finditer(text):
        changed = True
        if m.start() > cursor:
            parts.append(text[cursor : m.start()])
            starts.extend(range(cursor, m.start()))
            ends.extend(range(cursor + 1, m.start() + 1))
        if m["pct"] is not None:
            out = chr(int(m["pct"], 16))
        elif m["uni"] is not None:
            out = chr(int(m["uni"], 16))
        elif m["esc"] is not None:
            out = _JSON_ESCAPES[m["esc"]]
        else:
            out = ""
        if out:
            parts.append(out)
            starts.append(m.start())
            ends.append(m.end())
        cursor = m.end()
    if not changed:
        return None
    if cursor < len(text):
        parts.append(text[cursor:])
        starts.extend(range(cursor, len(text)))
        ends.extend(range(cursor + 1, len(text) + 1))
    return View("".join(parts), starts, ends)


def normalised_view(text: str) -> View | None:
    """The normalised view of *text*, or None when normalising changes nothing."""
    view: View | None = None
    for _ in range(_MAX_ROUNDS):
        layer = _one_round(text if view is None else view.text)
        if layer is None:
            break
        if view is not None:
            # Map the new layer straight to the original text.
            layer = View(
                layer.text,
                [view.starts[i] for i in layer.starts],
                [view.ends[i - 1] for i in layer.ends],
            )
        view = layer
    if view is None or not view.text:
        return None
    return view


def changed_windows(text: str, pad: int) -> list[tuple[int, int]]:
    """The source ranges normalising can change, each widened by *pad* a side.

    A rule run over the view can only find something new near a character the
    view changes, within that rule's own reach; *pad* is the largest reach. The
    windows are merged and sorted, and cost one scan of *text*.
    """
    windows: list[tuple[int, int]] = []
    for m in _TOKEN_RE.finditer(text):
        lo, hi = max(0, m.start() - pad), min(len(text), m.end() + pad)
        if windows and lo <= windows[-1][1]:
            windows[-1] = (windows[-1][0], max(windows[-1][1], hi))
        else:
            windows.append((lo, hi))
    return windows
