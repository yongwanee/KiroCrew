"""Vendor secret-rule catalog scanner (ported from Betterleaks, MIT).

The rule table lives in ``kiro_crew/data/secret_catalog.generated.json``, written
by ``scripts/gen_secret_catalog.py`` from an upstream release; see that script
for what is ported and how to regenerate. This module only loads the table and
scans text with it. It is stdlib only, makes no network call, and never
validates a finding against a vendor.

:func:`catalog_findings` returns the span of the SECRET part of every Secret-tier
finding. A caller that redacts merges overlapping spans itself.

A finding is dropped, in this order, when:

1. the secret's Shannon entropy is below the rule's floor;
2. the rule's allow-list (or the global allow-list) matches the secret;
3. the whole secret is an identifier shape (:func:`is_identifier_value`): an AWS
   key id, a UUID, a 40- or 64-character hex digest, a 12-digit account number
   or an ARN. Those name a thing and cannot authenticate, so they stay readable.
   A vendor whose own token format IS hex or a UUID (its rule spells a hex-only
   character class) keeps its finding when the value is hex or a UUID: there the
   vendor's keyword and label, not the value's shape, say what the value is.

Identifier-tier rules are loaded for :func:`catalog_rule_tier` but never report.
"""

from __future__ import annotations

import json
import math
import re
import threading
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kiro_crew.credential_patterns import TIER_IDENTIFIER, TIER_SECRET
from kiro_crew.credential_values import NAMING_VALUE

CATALOG_PATH = Path(__file__).resolve().parent.parent / "data" / "secret_catalog.generated.json"

#: Prefix on every rule id this module reports, so a merged record names its source.
RULE_PREFIX = "catalog:"

#: Identifier shapes no secret ever takes: an AWS key id, an account number, an ARN.
_NAMING_VALUE = re.compile(NAMING_VALUE, re.ASCII)
#: Identifier shapes some vendors also use for secrets: a UUID, a 40- or 64-hex digest.
_HEX_VALUE = re.compile(
    r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
    r"|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{64}",
    re.ASCII,
)
#: A character class made only of hex digits (``[a-f0-9]``, ``[0-9A-F]``, ...): a
#: rule that spells one expects a hex or UUID secret.
_HEX_CLASS = re.compile(r"\[[0-9a-fA-F-]+\]")


@dataclass(frozen=True)
class _Rule:
    rule_id: str
    tier: str
    regex: re.Pattern[str]
    secret_group: int
    keywords: tuple[str, ...]
    entropy_min: float | None
    allow: tuple[re.Pattern[str], ...]
    stopwords: tuple[str, ...]
    hex_secret: bool


@dataclass(frozen=True)
class _Catalog:
    rules: tuple[_Rule, ...]
    by_id: dict[str, _Rule]
    global_allow: tuple[re.Pattern[str], ...]
    #: The Secret-tier rules, and the keyword index over them.
    secret_rules: tuple[_Rule, ...] = ()
    keywordless: tuple[int, ...] = ()
    rules_by_keyword: dict[str, tuple[int, ...]] = field(default_factory=dict)
    #: Every keyword, longest first, matched at each position (a look-ahead).
    keyword_re: re.Pattern[str] = re.compile(r"(?!)")
    #: Each keyword with every keyword that is a substring of it.
    keyword_closure: dict[str, frozenset[str]] = field(default_factory=dict)
    #: The first three characters of every keyword (all are 3+ long).
    keyword_heads: frozenset[str] = frozenset()


def _keyword_index(rules: tuple[_Rule, ...]) -> dict[str, Any]:
    """The Secret-tier keyword index :class:`_Catalog` keeps."""
    secret = tuple(rule for rule in rules if rule.tier == TIER_SECRET)
    by_keyword: dict[str, list[int]] = {}
    for i, rule in enumerate(secret):
        for keyword in rule.keywords:
            by_keyword.setdefault(keyword, []).append(i)
    words = sorted(by_keyword, key=len, reverse=True)
    pattern = "|".join(re.escape(w) for w in words) or "(?!)"
    return {
        "secret_rules": secret,
        "keywordless": tuple(i for i, rule in enumerate(secret) if not rule.keywords),
        "rules_by_keyword": {k: tuple(v) for k, v in by_keyword.items()},
        "keyword_re": re.compile(f"(?=({pattern}))"),
        "keyword_closure": {w: frozenset(x for x in words if x in w) for w in words},
        "keyword_heads": frozenset(w[:3] for w in words),
    }


_lock = threading.Lock()
_catalog: _Catalog | None = None


def _compile(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.ASCII)


def _load() -> _Catalog:
    global _catalog
    if _catalog is not None:
        return _catalog
    with _lock:
        if _catalog is None:
            data = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
            rules = tuple(
                _Rule(
                    rule_id=RULE_PREFIX + raw["id"],
                    tier=raw["tier"],
                    regex=_compile(raw["regex"]),
                    secret_group=int(raw["secret_group"]),
                    keywords=tuple(raw["keywords"]),
                    entropy_min=raw["entropy_min"],
                    allow=tuple(_compile(p) for p in raw["allow_regexes"]),
                    stopwords=tuple(raw["stopwords"]),
                    hex_secret=_HEX_CLASS.search(raw["regex"]) is not None,
                )
                for raw in data["rules"]
            )
            _catalog = _Catalog(
                rules=rules,
                by_id={rule.rule_id: rule for rule in rules},
                global_allow=tuple(_compile(p) for p in data.get("global_allow_regexes", [])),
                **_keyword_index(rules),
            )
    return _catalog


def shannon_entropy(value: str) -> float:
    """Shannon entropy in bits per character (the upstream definition)."""
    if not value:
        return 0.0
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in Counter(value).values())


def is_naming_value(value: str) -> bool:
    """True when the WHOLE value is a key ID, an account ID or an ARN: names only."""
    return _NAMING_VALUE.fullmatch(value) is not None


def is_identifier_value(value: str) -> bool:
    """True when the WHOLE value is an identifier shape that cannot authenticate."""
    return _NAMING_VALUE.fullmatch(value) is not None or _HEX_VALUE.fullmatch(value) is not None


def catalog_rule_ids() -> tuple[str, ...]:
    """Every loaded rule id (both tiers), in catalog order."""
    return tuple(rule.rule_id for rule in _load().rules)


def catalog_rule_tier(rule_id: str) -> str:
    """``'secret'`` or ``'identifier'`` for a loaded rule id; ``KeyError`` otherwise."""
    tier = _load().by_id[rule_id].tier
    return TIER_IDENTIFIER if tier == TIER_IDENTIFIER else TIER_SECRET


def _secret_span(rule: _Rule, match: re.Match[str]) -> tuple[int, int]:
    """The secret's span: the rule's group, the whole match for ``-1``, else the first group."""
    if rule.secret_group < 0:
        return match.span()
    if rule.secret_group:
        return match.span(rule.secret_group)
    for group in range(1, (match.re.groups or 0) + 1):
        start, end = match.span(group)
        if end > start:
            return start, end
    return match.span()


def _dropped(rule: _Rule, secret: str, global_allow: tuple[re.Pattern[str], ...]) -> bool:
    if rule.entropy_min is not None and shannon_entropy(secret) < rule.entropy_min:
        return True
    if any(p.search(secret) for p in rule.allow) or any(p.search(secret) for p in global_allow):
        return True
    lowered = secret.lower()
    if any(word in lowered for word in rule.stopwords):
        return True
    if _NAMING_VALUE.fullmatch(secret) is not None:
        return True
    return not rule.hex_secret and _HEX_VALUE.fullmatch(secret) is not None


#: Below this length one pass of the keyword regex is cheaper than a substring
#: search per rule; above it the per-rule search (C-level ``in``) is.
_KEYWORD_SCAN_MAX = 4096


def _candidate_rules(catalog: _Catalog, lowered: str) -> list[_Rule]:
    """The Secret-tier rules whose keywords occur in *lowered*, in catalog order."""
    if len(lowered) > _KEYWORD_SCAN_MAX:
        return [
            rule
            for rule in catalog.secret_rules
            if not rule.keywords or any(k in lowered for k in rule.keywords)
        ]
    # Each keyword occurrence starts where the longest-first alternation matches
    # some keyword that it is a prefix of, so the closure finds every one.
    indexes = set(catalog.keywordless)
    for m in catalog.keyword_re.finditer(lowered):
        for keyword in catalog.keyword_closure[m.group(1)]:
            indexes.update(catalog.rules_by_keyword[keyword])
    return [catalog.secret_rules[i] for i in sorted(indexes)]


def has_catalog_keyword(text: str) -> bool:
    """Whether *text* holds any Secret-tier rule keyword (a cheap pre-scan)."""
    lowered = text.lower()
    catalog = _load()
    if len(lowered) > _KEYWORD_SCAN_MAX:
        return any(k in lowered for k in catalog.rules_by_keyword)
    # Every keyword is 3+ characters, so one must start at a position whose
    # three characters begin some keyword: a set lookup per position first.
    heads = catalog.keyword_heads
    if not any(lowered[i : i + 3] in heads for i in range(len(lowered) - 2)):
        return False
    return catalog.keyword_re.search(lowered) is not None


def catalog_keyword_start(text: str, lo: int = 0) -> int | None:
    """Where the first Secret-tier rule keyword at or after *lo* starts, or None.

    A rule's match starts near its keyword, so the stream holds from here while
    the match may still be arriving.
    """
    # A match still arriving spans at most the last three blank-separated tokens
    # (keyword, separator, value), so only those are scanned.
    i, blanks, in_blank = len(text), 0, False
    while i > lo:
        if text[i - 1].isspace():
            if not in_blank:
                blanks += 1
                if blanks == 3:
                    break
            in_blank = True
        else:
            in_blank = False
        i -= 1
    lo = i
    tail = text[lo:]
    lowered = tail.lower()
    heads = _load().keyword_heads
    if not any(lowered[j : j + 3] in heads for j in range(len(lowered) - 2)):
        return None
    for m in _load().keyword_re.finditer(lowered):
        # Still arriving: the keyword's token, then optionally the catalog's
        # assignment separator and a value, running to the end.
        if "[REDACTED" in tail[m.start() :]:
            continue  # what follows is already a tag, not a value
        if _CATALOG_ARRIVING_RE.fullmatch(tail, m.start()) is not None:
            return lo + m.start()
    return None


#: What follows a catalog keyword while its rule's match may still be arriving:
#: the rest of its token, the upstream assignment operator set and a value
#: with no blank after it yet.
_CATALOG_ARRIVING_RE = re.compile(
    r"""\S{0,48}[\s'"]{0,3}(?:(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[`'"\s=]{0,5}\S{0,200})?"""
)


def catalog_findings(text: str) -> list[tuple[int, int, str]]:
    """``(start, end, rule_id)`` of each Secret-tier finding's secret, sorted by start."""
    if not text:
        return []
    catalog = _load()
    lowered = text.lower()
    findings: list[tuple[int, int, str]] = []
    for rule in _candidate_rules(catalog, lowered):
        for match in rule.regex.finditer(text):
            start, end = _secret_span(rule, match)
            if start < 0 or end <= start:
                continue
            if _dropped(rule, text[start:end], catalog.global_allow):
                continue
            findings.append((start, end, rule.rule_id))
    findings.sort(key=lambda f: (f[0], f[1], f[2]))
    return findings
