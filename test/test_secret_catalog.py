"""The ported vendor secret-rule catalog: shape, translation, tiers and coverage.

Every positive sample here is GENERATED AT TEST TIME from the rule's own regex,
so no credential-shaped value is ever written to the repository. The generator
is a small, seeded walk over ``re._parser``'s parse tree.
"""

from __future__ import annotations

import importlib.util
import json
import random
import re
import sys
import zlib
from pathlib import Path
from re import _constants as sre_c  # type: ignore[attr-defined]
from re import _parser as sre_parse  # type: ignore[attr-defined]
from typing import Any

import pytest

from kiro_crew.credential_patterns import TIER_IDENTIFIER, TIER_SECRET
from kiro_crew.security import secret_catalog as sc

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR_PATH = REPO_ROOT / "scripts" / "gen_secret_catalog.py"


def _load_generator() -> Any:
    spec = importlib.util.spec_from_file_location("gen_secret_catalog", GENERATOR_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_secret_catalog"] = module
    spec.loader.exec_module(module)
    return module


gen = _load_generator()
CATALOG = json.loads(sc.CATALOG_PATH.read_text(encoding="utf-8"))

#: Secret-tier rules the generator below cannot produce a surviving sample for,
#: with the reason. This list may only shrink.
UNSAMPLEABLE: dict[str, str] = {}
UNSAMPLEABLE_CEILING = 0


# ---------------------------------------------------------------------------
# Runtime sample generator
# ---------------------------------------------------------------------------

_ALNUM = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
_PRINTABLE = [chr(c) for c in range(0x21, 0x7F)]
_CATEGORY_CHARS = {
    sre_c.CATEGORY_DIGIT: "0123456789",
    sre_c.CATEGORY_WORD: _ALNUM + "_",
    sre_c.CATEGORY_SPACE: " ",
    sre_c.CATEGORY_NOT_DIGIT: _ALNUM[:52],
    sre_c.CATEGORY_NOT_WORD: "-.:/+",
    sre_c.CATEGORY_NOT_SPACE: _ALNUM,
}


def _class_members(items: list[tuple[Any, Any]]) -> tuple[bool, set[str]]:
    negate = False
    members: set[str] = set()
    for op, av in items:
        if op is sre_c.NEGATE:
            negate = True
        elif op is sre_c.LITERAL:
            members.add(chr(av))
        elif op is sre_c.RANGE:
            lo, hi = av
            members.update(chr(c) for c in range(max(lo, 0x20), min(hi, 0x7E) + 1))
        elif op is sre_c.CATEGORY:
            members.update(_CATEGORY_CHARS.get(av, ""))
    return negate, members


def _pick_class(items: list[tuple[Any, Any]], rng: random.Random) -> str:
    categories = {av for op, av in items if op is sre_c.CATEGORY}
    if {sre_c.CATEGORY_SPACE, sre_c.CATEGORY_NOT_SPACE} <= categories:
        # ``[\s\S]``: any character, sampled as ``.`` is.
        return rng.choice(_ALNUM + "  ::==")
    negate, members = _class_members(items)
    if negate:
        pool = [c for c in _ALNUM if c not in members] or [
            c for c in _PRINTABLE if c not in members
        ]
    else:
        pool = sorted(members)
        nonspace = [c for c in pool if not c.isspace()]
        pool = nonspace or pool
    return rng.choice(pool) if pool else "x"


def _sample(tree: Any, rng: random.Random, groups: dict[int, str]) -> str:
    out: list[str] = []
    for op, av in tree:
        if op is sre_c.LITERAL:
            out.append(chr(av))
        elif op is sre_c.NOT_LITERAL:
            out.append(rng.choice([c for c in _ALNUM if c != chr(av)]))
        elif op is sre_c.ANY:
            # Mostly word characters, sometimes a separator so a following \b holds.
            out.append(rng.choice(_ALNUM + "  ::=="))
        elif op is sre_c.IN:
            out.append(_pick_class(av, rng))
        elif op is sre_c.CATEGORY:
            out.append(rng.choice(_CATEGORY_CHARS.get(av, "x")))
        elif op in (sre_c.MAX_REPEAT, sre_c.MIN_REPEAT, sre_c.POSSESSIVE_REPEAT):
            lo, hi, sub = av
            top = lo + rng.choice((0, 2, 8, 24)) if hi is sre_c.MAXREPEAT else min(hi, lo + 24)
            count = rng.randint(lo, max(lo, top))
            out.extend(_sample(sub, rng, groups) for _ in range(count))
        elif op is sre_c.SUBPATTERN:
            group, _add, _del, sub = av
            text = _sample(sub, rng, groups)
            if group:
                groups[group] = text
            out.append(text)
        elif op is sre_c.ATOMIC_GROUP:
            out.append(_sample(av, rng, groups))
        elif op is sre_c.BRANCH:
            out.append(_sample(rng.choice(av[1]), rng, groups))
        elif op is sre_c.GROUPREF:
            out.append(groups.get(av, ""))
        elif op is sre_c.GROUPREF_EXISTS:
            out.append(_sample(av[1], rng, groups))
        # AT, ASSERT and ASSERT_NOT consume nothing; the retry loop absorbs them.
    return "".join(out)


def _rule(rule_id: str) -> Any:
    return sc._load().by_id[rule_id]


def _sample_outcome(rule_id: str, attempts: int = 300) -> str:
    """Generate samples until one is reported; return how the rule behaved.

    ``"reported"``: a finding covers the generated secret. ``"vetoed"``: every
    matching sample's whole secret was an identifier shape, and none of them was
    reported -- the identifier value veto working as designed. ``"missed"``:
    neither. Each sample sits on its own line after a line naming one of the
    rule's keywords, as real configuration does.
    """
    rule = _rule(rule_id)
    tree = sre_parse.parse(rule.regex.pattern, re.ASCII)
    rng = random.Random(zlib.crc32(rule_id.encode()))
    keywords = list(rule.keywords) or [""]
    vetoed = 0
    dropped = 0
    for _ in range(attempts):
        text = f"{rng.choice(keywords)}\nconfig: {_sample(tree, rng, {})}\n"
        match = rule.regex.search(text)
        if match is None:
            continue
        start, end = sc._secret_span(rule, match)
        if end <= start:
            continue
        covering = [
            f
            for f in sc.catalog_findings(text)
            if f[2] == rule_id and f[0] <= start and f[1] >= end
        ]
        if covering:
            return "reported"
        if sc.is_identifier_value(text[start:end]):
            vetoed += 1
        else:
            dropped += 1
    return "vetoed" if vetoed and not dropped else "missed"


SECRET_RULE_IDS = [r for r in sc.catalog_rule_ids() if sc.catalog_rule_tier(r) == TIER_SECRET]


@pytest.mark.parametrize("rule_id", SECRET_RULE_IDS)
def test_secret_rule_reports_a_generated_sample(rule_id: str) -> None:
    if rule_id in UNSAMPLEABLE:
        pytest.skip(UNSAMPLEABLE[rule_id])
    assert _sample_outcome(rule_id) == "reported", rule_id


def test_unsampleable_list_does_not_grow() -> None:
    assert len(UNSAMPLEABLE) <= UNSAMPLEABLE_CEILING
    assert set(UNSAMPLEABLE) <= set(SECRET_RULE_IDS)


# ---------------------------------------------------------------------------
# Identifier tier and the identifier value veto
# ---------------------------------------------------------------------------


def _identifier_values() -> dict[str, str]:
    rng = random.Random(7)
    hex_chars = "0123456789abcdef"

    def hexes(n: int) -> str:
        return "".join(rng.choice(hex_chars) for _ in range(n))

    return {
        "uuid": f"{hexes(8)}-{hexes(4)}-{hexes(4)}-{hexes(4)}-{hexes(12)}",
        "uuid_upper": f"{hexes(8)}-{hexes(4)}-{hexes(4)}-{hexes(4)}-{hexes(12)}".upper(),
        "git_sha": hexes(40),
        "sha256": hexes(64),
        "account_id": "".join(rng.choice("0123456789") for _ in range(12)),
        "arn": "arn:aws:iam::" + "".join(rng.choice("0123456789") for _ in range(12)) + ":role/x",
        # The AWS documentation example key id, assembled so no file holds it whole.
        "aws_doc_key_id": "AKIA" + "IOSFODNN7" + "EXAMPLE",
    }


@pytest.mark.parametrize("label", ["", "api_key = ", "secret: ", "token="])
@pytest.mark.parametrize("kind", sorted(_identifier_values()))
def test_identifier_values_are_never_reported(kind: str, label: str) -> None:
    value = _identifier_values()[kind]
    text = f"{label}{value}\n"
    start = len(label)
    end = start + len(value)
    overlapping = [f for f in sc.catalog_findings(text) if f[0] < end and f[1] > start]
    assert overlapping == []


@pytest.mark.parametrize("kind", sorted(_identifier_values()))
def test_identifier_values_hit_the_veto(kind: str) -> None:
    assert sc.is_identifier_value(_identifier_values()[kind])


def test_veto_needs_the_whole_value() -> None:
    assert not sc.is_identifier_value(_identifier_values()["git_sha"] + "zz")
    assert not sc.is_identifier_value("x" + _identifier_values()["account_id"])


def test_aws_key_id_rule_is_identifier_tier() -> None:
    assert sc.catalog_rule_tier("catalog:aws-access-token") == TIER_IDENTIFIER


IDENTIFIER_RULE_IDS = [
    r for r in sc.catalog_rule_ids() if sc.catalog_rule_tier(r) == TIER_IDENTIFIER
]


@pytest.mark.parametrize("rule_id", IDENTIFIER_RULE_IDS)
def test_identifier_tier_rule_never_reports(rule_id: str) -> None:
    rule = _rule(rule_id)
    tree = sre_parse.parse(rule.regex.pattern, re.ASCII)
    rng = random.Random(zlib.crc32(rule_id.encode()))
    keywords = list(rule.keywords) or [""]
    for _ in range(20):
        text = f"{rng.choice(keywords)}\nconfig: {_sample(tree, rng, {})}\n"
        assert rule_id not in {f[2] for f in sc.catalog_findings(text)}


# ---------------------------------------------------------------------------
# Go RE2 -> Python translation
# ---------------------------------------------------------------------------


def test_mid_pattern_flag_is_scoped_to_the_rest_of_the_group() -> None:
    py = gen.translate_go_regex("ab(?i)cd")
    assert py == "ab(?i:cd)"
    assert re.fullmatch(py, "abCD") and not re.fullmatch(py, "ABcd")


def test_mid_pattern_flag_carries_into_later_branches() -> None:
    # RE2 reads X(?i)Y|Z as XY|Z with the flag on Y and on Z.
    py = gen.translate_go_regex("x(?i)y|z")
    assert re.fullmatch(py, "xY") and re.fullmatch(py, "Z")
    assert not re.fullmatch(py, "XY")


def test_flag_inside_a_group_stays_inside_it() -> None:
    py = gen.translate_go_regex("(?:a(?i)b|c)d")
    assert re.fullmatch(py, "aBd") and re.fullmatch(py, "Cd")
    assert not re.fullmatch(py, "aBD")


def test_backslash_z_becomes_end_of_text() -> None:
    py = gen.translate_go_regex(r"abc\z")
    assert py == r"abc\Z"
    assert re.search(py, "abc") and not re.search(py, "abc\n")


def test_posix_class_becomes_ascii_ranges() -> None:
    py = gen.translate_go_regex("[[:alnum:]_]{3}")
    assert py == "[a-zA-Z0-9_]{3}"
    assert re.fullmatch(py, "a_9") and not re.fullmatch(py, "a-9")


def test_dollar_is_kept_and_also_matches_before_a_final_newline() -> None:
    # Pinned choice: Python's $ also matches just before a trailing newline,
    # which can only widen a match by that one position.
    py = gen.translate_go_regex("abc$")
    assert py == "abc$"
    assert re.search(py, "abc\n") and not re.search(py, "abc\nx")


def test_named_group_and_hex_escape() -> None:
    py = gen.translate_go_regex(r"(?<k>\x{41})")
    assert py == r"(?P<k>\x41)"
    assert re.fullmatch(py, "A")


def test_unsupported_construct_raises() -> None:
    with pytest.raises(gen.UnsupportedRegex):
        gen.translate_go_regex(r"\pL+")


#: Upstream's ``curl-auth-header`` pattern, as written for RE2.
_CURL_AUTH_HEADER_GO = "\\bcurl\\b(?:.*?|.*?(?:[\\r\\n]{1,2}.*?){1,5})[ \\t\\n\\r](?:-H|--header)(?:=|[ \\t]{0,5})(?:\"(?i)(?:Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))\"|'(?i)(?:Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))')(?:\\B|\\s|\\z)"


def test_curl_auth_header_translates_and_matches_its_shape() -> None:
    """Its scoped flag spans an alternation; the translation keeps RE2's meaning.

    The rule itself is not ported (a backtracking engine is not linear-time on
    it), so the translation is checked on its own.
    """
    regex = re.compile(gen.translate_go_regex(_CURL_AUTH_HEADER_GO), re.ASCII)
    sample = "x" * 6 + "Q7" + "z" * 4 + "R2" + "w" * 6
    for quote in ('"', "'"):
        text = f"curl -H {quote}authorization: bearer {sample}{quote} https://h.invalid\n"
        assert regex.search(text) is not None
    assert {"id": "curl-auth-header", "reason": "regex-unsupported"} in CATALOG["skipped"]


def test_filter_subset() -> None:
    assert gen.parse_filter('entropy(finding["secret"]) <= 3.5') == (3.5, [])
    entropy, allow = gen.parse_filter(
        'filter.entropy(finding["secret"]) < 3 || filter.tokenRatio(finding["secret"]) >= 2.5'
        ' || matchesAny(finding["secret"], [`^a`, "b$"]) || containsAny(finding["secret"], ["c.d"])'
    )
    assert entropy == 3.0 and allow == ["^a", "b$", r"c\.d"]
    for program in (
        "let x = 1; x > 0",
        'matchesAny(finding["match"], [`a`])',
        'entropy(finding["secret"]) < 3 && matchesAny(finding["secret"], [`a`])',
        '!matchesAny(finding["secret"], [`a`])',
    ):
        with pytest.raises(gen.UnsupportedFilter):
            gen.parse_filter(program)


# ---------------------------------------------------------------------------
# Generated JSON shape
# ---------------------------------------------------------------------------


def test_license_and_source_are_carried() -> None:
    assert "MIT License" in CATALOG["_license"]
    assert "Copyright (c) 2026 Zachary Rice" in CATALOG["_license"]
    assert CATALOG["_source"].startswith("betterleaks v1.9.0 config/betterleaks.toml @ ")
    assert "gen_secret_catalog.py" in CATALOG["_generated_by"]


def test_rule_shape_ids_and_compilation() -> None:
    ids = [r["id"] for r in CATALOG["rules"]]
    assert len(ids) == len(set(ids))
    assert not set(ids) & {s["id"] for s in CATALOG["skipped"]}
    keys = {
        "id",
        "tier",
        "regex",
        "secret_group",
        "keywords",
        "entropy_min",
        "allow_regexes",
        "stopwords",
    }
    for raw in CATALOG["rules"]:
        assert set(raw) == keys
        assert raw["tier"] in (TIER_SECRET, TIER_IDENTIFIER)
        compiled = re.compile(raw["regex"], re.ASCII)
        assert raw["secret_group"] <= compiled.groups
        assert raw["entropy_min"] is None or isinstance(raw["entropy_min"], float)
        assert all(k == k.lower() for k in raw["keywords"])
        for pattern in raw["allow_regexes"]:
            re.compile(pattern, re.ASCII)
    for pattern in CATALOG["global_allow_regexes"]:
        re.compile(pattern, re.ASCII)


def test_skip_reasons_come_from_the_fixed_set() -> None:
    assert {s["reason"] for s in CATALOG["skipped"]} <= set(gen.SKIP_REASONS)


def test_json_is_rendered_deterministically() -> None:
    assert gen.render(CATALOG) == sc.CATALOG_PATH.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------
# Benign prose and speed
# ---------------------------------------------------------------------------

#: Findings per MB of the repository's own Markdown docs.
DOCS_FINDINGS_PER_MB_CEILING = 1.0


def test_repository_docs_stay_quiet() -> None:
    total_bytes = 0
    findings = 0
    for path in sorted((REPO_ROOT / "docs").rglob("*.md")):
        text = path.read_text(encoding="utf-8", errors="replace")
        total_bytes += len(text.encode("utf-8"))
        findings += len(sc.catalog_findings(text))
    assert total_bytes > 0
    assert findings / (total_bytes / 1_000_000) <= DOCS_FINDINGS_PER_MB_CEILING


def test_no_ported_rule_keeps_an_ambiguous_any_character_branch() -> None:
    """``(?:.|[\\n\\r])`` is one class to RE2 but an exponential branch point to a
    backtracking engine; the generator spells it ``[\\s\\S]``."""
    for rule in CATALOG["rules"]:
        for ambiguous in ("(?:.|[\\n\\r])", "(?:.|[\\r\\n])", "(?:.|\\n)", "(?:.|\\r)"):
            assert ambiguous not in rule["regex"], rule["id"]


def test_a_rule_with_several_structural_groups_redacts_its_whole_match() -> None:
    teams = sc._load().by_id["catalog:microsoft-teams-webhook"]
    assert teams.secret_group == -1


def test_a_vendor_whose_token_is_hex_keeps_its_finding() -> None:
    """A rule that spells a hex-only class reports a hex value; others veto it."""
    rules = [r for r in sc._load().rules if r.tier == TIER_SECRET and r.entropy_min is None]
    hex_rules = [r for r in rules if r.hex_secret]
    other = [r for r in rules if not r.hex_secret]
    assert hex_rules and other
    value = _identifier_values()["uuid"]
    assert not sc._dropped(hex_rules[0], value, ())
    assert sc._dropped(other[0], value, ())
    assert sc._dropped(hex_rules[0], _identifier_values()["aws_doc_key_id"], ())
