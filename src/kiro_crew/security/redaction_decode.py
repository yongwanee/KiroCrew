"""Encoded credentials: a base64 run that decodes to a secret.

Pass 2 of the batch redactor. A run of the base64 alphabet (standard or
URL-safe, on one line or wrapped over several) is decoded, and the decoded text
is checked with the same rules the plain text is; when it holds a secret, the
whole encoded run is replaced.

:mod:`kiro_crew.security.redaction` is the import path of every name defined
here.
"""

from __future__ import annotations

import base64
import binascii
import re
from collections.abc import Iterator

from kiro_crew.credential_patterns import URL_SIGNING_VALUE

from .redaction_labels import (
    BLOCKING_RULE_IDS,
    QUOTED_HOLD_REACH,
    has_context_hint,
    label_spans,
    paired_secret_spans,
    uri_password_spans,
)
from .redaction_normalise import changed_windows, normalised_view
from .redaction_patterns import (
    _PREFILTER_MIN_LEN,
    _contains_credential_pattern,
    _might_contain_credential,
)
from .secret_catalog import catalog_findings, has_catalog_keyword

# Base64 alphabet: at least 40 chars of [A-Za-z0-9+/] ending with optional =
_B64_CHUNK_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

#: The URL-safe alphabet (``-`` and ``_`` for ``+`` and ``/``). Only a run that
#: carries one of the two URL-safe characters is a URL-safe candidate; any other
#: run is already a standard chunk.
_B64URL_CHUNK_RE = re.compile(r"(?<![A-Za-z0-9_-])(?=[A-Za-z0-9_-]*[_-])[A-Za-z0-9_-]{40,}={0,2}")

#: Base64 wrapped over lines, as PEM bodies, MIME parts and ``base64`` (default
#: 76 columns) write it: one or more full lines, each ended by a newline or a
#: literal ``\n``, then a last line.
_B64_WRAPPED_RE = re.compile(
    r"(?<![A-Za-z0-9+/])(?:[A-Za-z0-9+/]{16,}(?:\r?\n|\\n))+[A-Za-z0-9+/]{4,}={0,2}"
)
_LINE_BREAK_RE = re.compile(r"\r?\n|\\n")

# A presigned/signed link's signing value. A base64-encoded SigV2 link decodes to
# a URL whose ``&Signature=<base64>`` is not a pass-1 shape, so the decoded text is
# also checked for it.
_URL_SIGNING_RE = re.compile(URL_SIGNING_VALUE)


def _holds_secret(decoded: str) -> bool:
    """Whether decoded text, or its normalised view (escapes and percent-codes
    read, never base64 again), holds anything the plain-text rules redact."""
    if _holds_plain_secret(decoded):
        return True
    view = normalised_view(decoded)
    return view is not None and _holds_plain_secret(view.text)


def _holds_plain_secret(decoded: str) -> bool:
    """Whether *decoded*, as written, holds anything the plain-text rules redact."""
    if _URL_SIGNING_RE.search(decoded) is not None:
        return True
    # Gate the alternation behind the cheap superset pre-filter, as pass 1 does;
    # below `_PREFILTER_MIN_LEN` the alternation is the cheaper of the two.
    if len(decoded) < _PREFILTER_MIN_LEN or _might_contain_credential(decoded):
        if _contains_credential_pattern(decoded):
            return True
    # The context rules all start at a keyword: a label, a key ID prefix, a URI
    # scheme or a vendor-catalog keyword. Decoded text with none of them (the
    # random bytes most base64 runs in a large file decode to) holds no match.
    if not has_context_hint(decoded) and not has_catalog_keyword(decoded):
        return False
    return bool(
        label_spans(decoded)
        or paired_secret_spans(decoded)
        or uri_password_spans(decoded)
        or catalog_findings(decoded)
    )


def _decode(chunk: str, *, urlsafe: bool = False) -> str:
    """*chunk* decoded as UTF-8 text (invalid bytes dropped), or ``""``."""
    # NO LENGTH SHORT-CIRCUIT: base64 padding leniency differs across Python
    # versions, so whether a chunk decodes is left to the decoder itself.
    try:
        if urlsafe:
            raw = base64.urlsafe_b64decode(chunk + "=" * (-len(chunk.rstrip("=")) % 4))
        else:
            raw = base64.b64decode(chunk, validate=True)
    except (binascii.Error, ValueError):
        return ""
    return raw.decode("utf-8", errors="ignore")


def _decode_b64_chunk(chunk: str) -> str:
    """Decode ONE standard `_B64_CHUNK_RE` match; return it when it holds a secret, else ''."""
    decoded = _decode(chunk)
    return decoded if decoded and _holds_secret(decoded) else ""


def _decode_b64_safe(text: str) -> str:
    """The first standard base64 chunk in *text* that decodes to a secret, decoded, or ''."""
    for m in _B64_CHUNK_RE.finditer(text):
        decoded = _decode_b64_chunk(m.group())
        if decoded:
            return decoded
    return ""


def _contains_fixed_credential(text: str) -> bool:
    """Return True for a credential that blocks a request.

    Gates request-BLOCKING decisions in the exfiltration checks and the static
    preview: the fixed patterns and the context rules of the Secret tier (an AWS
    or ``Authorization`` label, a key pair, a catalog finding, an encoded
    credential), on the text and on its normalised view. A generic labelled
    value or a signing value redacts output but does not block.
    """
    return _contains_credential_pattern(text) or blocking_context(text) or _view_blocks(text)


def blocking_context(text: str) -> bool:
    """The context rules of :func:`_contains_fixed_credential`, without pass 1."""
    # Only a Secret-tier label blocks. A generic labelled value and a signing
    # value (Bearer link tier: it masks, as ``?token=`` does) are redacted in
    # output and are not, alone, grounds to refuse a request.
    if any(span.rule in BLOCKING_RULE_IDS for span in label_spans(text)):
        return True
    if paired_secret_spans(text) or catalog_findings(text):
        return True
    return bool(_decode_b64_safe(text))


def _view_blocks(text: str) -> bool:
    """Whether the normalised view, around the characters it changes, blocks."""
    for lo, hi in changed_windows(text, QUOTED_HOLD_REACH):
        view = normalised_view(text[lo:hi])
        if view is not None and (
            _contains_credential_pattern(view.text) or blocking_context(view.text)
        ):
            return True
    return False


def encoded_credential_spans(text: str) -> Iterator[tuple[int, int]]:
    """Spans of every base64 run in *text* that decodes to a secret.

    Standard runs first, then URL-safe and wrapped runs; spans may overlap and
    the caller merges them.
    """
    for m in _B64_CHUNK_RE.finditer(text):
        if _decode_b64_chunk(m.group()):
            yield m.span()
    for m in _B64URL_CHUNK_RE.finditer(text):
        decoded = _decode(m.group(), urlsafe=True)
        if decoded and _holds_secret(decoded):
            yield m.span()
    for m in _B64_WRAPPED_RE.finditer(text):
        decoded = _decode(_LINE_BREAK_RE.sub("", m.group()))
        if decoded and _holds_secret(decoded):
            yield m.span()
