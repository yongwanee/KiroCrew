"""Whether a value behind a secret label is a secret: the one shared predicate.

The batch redactor (:mod:`kiro_crew.security.redaction_labels`) and the log
filter (:mod:`kiro_crew.log_redaction`) both read a labelled value here, so the
two cannot drift apart. A value is a secret unless the WHOLE value is on a
short exemption list; nothing here guesses from a value's first characters or
from the code around it. Imports only the standard library and
:mod:`kiro_crew.credential_patterns`, so the log filter stays an import leaf.
"""

from __future__ import annotations

import re

from kiro_crew.credential_patterns import (
    AWS_KEY_ID_BODY,
    AWS_KEY_ID_PREFIXES,
    AWS_KEY_ID_REDACTION_ONLY_PREFIXES,
    REFERENCE_VALUE,
)

#: The shortest value a label rule redacts. Shorter values are flags, units and
#: words (``password: no``), not secrets.
MIN_VALUE_LEN = 8

#: The longest quoted value read through to its closing quote, in every reader.
QUOTED_MAX = 512

#: A one-case run of letters this long is a passphrase, not a word.
WORD_LEN_MAX = 15

_REFERENCE_RE = re.compile(REFERENCE_VALUE)

#: A whole redaction tag (``[REDACTED: credential]``): a fixed point, not a value.
_TAG_RE = re.compile(r"\[REDACTED[^\]\n]{0,64}\]")

#: A secret-store reference (``secret://name``, ``vault://path``, ``env:NAME``):
#: it names where a secret lives, and is not one.
_STORE_REFERENCE_RE = re.compile(r"(?i:[a-z][a-z0-9+.-]{1,15}://|(?:env|ssm|op|keychain):)")

#: A value that can only NAME something: an AWS key ID, a 12-digit account ID,
#: an ARN. Identifier tier, so it is never redacted behind a label.
NAMING_VALUE = (
    rf"(?:{AWS_KEY_ID_PREFIXES}|{AWS_KEY_ID_REDACTION_ONLY_PREFIXES}){AWS_KEY_ID_BODY}"
    r"|[0-9]{12}|arn:[a-z0-9-]+:\S*"
)
_NAMING_RE = re.compile(NAMING_VALUE, re.ASCII)


def value_extent(text: str, start: int, quote: str) -> int:
    """End of a value opened by *quote* at *start*: its unescaped closing quote.

    The extent depends on the quote state only. A value still open at the line
    end, the text end or after :data:`QUOTED_MAX` characters ends there, so it
    is removed whole up to that point rather than cut at its first delimiter.
    """
    pos = start
    limit = min(len(text), start + QUOTED_MAX)
    while pos < limit:
        char = text[pos]
        if char == "\\":
            pos += 2
            continue
        if char == quote or char == "\n":
            return pos
        pos += 1
    return min(pos, len(text))


def is_tag(value: str) -> bool:
    """Whether *value* is a whole redaction tag."""
    return _TAG_RE.fullmatch(value) is not None


def is_naming_value(value: str) -> bool:
    """True when the WHOLE value is a key ID, an account ID or an ARN: names only."""
    return _NAMING_RE.fullmatch(value) is not None


def _is_dotted_name(value: str) -> bool:
    """A chain of two or more names of letters and ``_`` (``settings.aws_key``)."""
    parts = value.split(".")
    return len(parts) > 1 and all(p and p.isascii() and p.replace("_", "").isalpha() for p in parts)


def _is_word(value: str) -> bool:
    """A single-case word of letters at most :data:`WORD_LEN_MAX` long."""
    return value.isalpha() and (value.islower() or value.isupper()) and len(value) <= WORD_LEN_MAX


def is_exempt_value(value: str, *, aws: bool = False, quoted: bool = False) -> bool:
    """Whether the WHOLE *value* names or masks a secret instead of holding one.

    The list: shorter than :data:`MIN_VALUE_LEN`; a reference or a mask
    (``$VAR``, ``${VAR}``, ``%VAR%``, ``{{ x }}``, ``<your key>``, ``****``); a
    secret-store reference; a redaction tag; a single-case word of letters no
    longer than :data:`WORD_LEN_MAX` (``password: required``); a dotted chain of
    letter names (``settings.aws_key``); a path (``/srv/app``, ``~/x``, ``./x``).
    Every test is on the whole value. A *quoted* value is a literal, so only a
    reference, a store reference or a tag exempts it, whatever its length.
    """
    if not value or is_tag(value):
        return True
    if _REFERENCE_RE.fullmatch(value) is not None or _STORE_REFERENCE_RE.match(value):
        return True
    if quoted:
        # A quoted value behind a secret label is a literal the writer chose to
        # quote: no length, word, dotted-name or path test applies to it.
        return False
    if len(value) < MIN_VALUE_LEN:
        return True
    if aws:
        # Behind an AWS secret label the value is the secret whatever it looks
        # like: no word or path exemption.
        return _is_dotted_name(value)
    if _is_word(value):
        return True
    return _is_dotted_name(value) or value.startswith(("/", "~/", "./", "../"))


def labelled_value_is_secret(
    value: str, *, quoted: bool, next_char: str, aws: bool = False
) -> bool:
    """Whether a value behind a secret label is a secret.

    It is, unless the whole value is exempt (:func:`is_exempt_value`), it can
    only name something (:func:`is_naming_value`), or, written unquoted, it is
    called or subscripted (*next_char* is ``(`` or ``[``: ``load_key(path)``,
    ``os.environ[...]``). Behind an AWS secret label (*aws*) a value shaped
    like a key ID is still the secret the label names, so it is not vetoed.
    """
    if is_exempt_value(value, aws=aws, quoted=quoted) or (not aws and is_naming_value(value)):
        return False
    return quoted or next_char not in ("(", "[")
