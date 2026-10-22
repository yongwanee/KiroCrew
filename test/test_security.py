"""Tests for security.py — credential redaction and sandbox denied commands."""

from __future__ import annotations

import base64
import hashlib
import json
import math
import os
import random
import re
import socket
import string
import struct
import sys
from collections import Counter
from collections.abc import Callable
from pathlib import Path

import pytest
import security_helpers
from oauth_url_corpus import OPERATOR_EXTENSION_OAUTH_URLS

from kiro_crew import security
from kiro_crew.security import (
    _SECRET_KEY_LEN,
    _SECRET_MAX_SLASHES,
    REDACTED_CREDENTIAL_TAG,
    is_sensitive_path,
    oauth_url_contains_credential,
    redact_credentials,
    redact_exfiltration_urls,
    sanitized_oauth_endpoint,
    sanitized_oauth_endpoint_display,
    scan_exfiltration_urls,
)

#: The canonical AWS documentation example secret access key. It CONTAINS
#: two ``/`` characters, which is what makes it the fixture for the
#: path-versus-secret boundary: a fix that treated every slash-bearing run
#: as a path would leak exactly this value.
_AWS_EXAMPLE_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
#: A second slash-bearing shape, so no claim about slash-bearing keys rests
#: on one fixture's particular letters.
_ALT_SLASH_KEY = "Kx3Q51tPusV/D0URlGfMmNbVc7Z8yJhLpQrStUwZ"
#: The same shape without separators, which the ceiling cannot reach.
_NO_SLASH_KEY = "Kx3Q51tPusVkD0URlGfMmNbVc7Z8yJhLpQrStUwZ"


class TestRedactCredentials:
    """Tests for redact_credentials()."""

    def test_redacts_aws_access_key_id(self) -> None:
        text = "Found key AKIAIOSFODNN7EXAMPLE in output"
        result, warnings = redact_credentials(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        assert "[REDACTED: credential]" in result
        assert len(warnings) == 1

    def test_redacts_asia_key(self) -> None:
        text = "ASIAXXXXXXXXXEXAMPLE"
        result, _ = redact_credentials(text)
        assert "ASIA" not in result

    def test_redacts_secret_access_key(self) -> None:
        text = "SecretAccessKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result, _ = redact_credentials(text)
        assert "wJalrXUtnFEMI" not in result

    def test_redacts_aws_secret_access_key_ini(self) -> None:
        text = "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG"
        result, _ = redact_credentials(text)
        assert "wJalrXUtnFEMI" not in result

    def test_redacts_session_token(self) -> None:
        text = "SessionToken=FwoGZXIvYXdzEBYaDH+longtoken"
        result, _ = redact_credentials(text)
        assert "FwoGZXIvYXdzEBYaDH" not in result

    def test_redacts_private_key_header(self) -> None:
        text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ"
        result, _ = redact_credentials(text)
        assert "BEGIN RSA PRIVATE KEY" not in result

    def test_redacts_openssh_private_key(self) -> None:
        text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1r"
        result, _ = redact_credentials(text)
        assert "BEGIN OPENSSH PRIVATE KEY" not in result

    def test_redacts_full_private_key_body(self) -> None:
        """security-review 05687e60: the base64 BODY (not just the header) must be redacted."""
        body_a = "MIIEpAIBAAKCAQEA1234567890abcdefghijklmnopqrstuvwxyzABCDEF"
        body_b = "GHIJKLMNOPQRSTUVWXYZ0987654321zyxwvutsrqponmlkjihgfedcba"
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            f"{body_a}\n{body_b}\n"
            "-----END RSA PRIVATE KEY-----"
        )
        result, warnings = redact_credentials(text)
        assert body_a not in result
        assert body_b not in result
        assert "BEGIN RSA PRIVATE KEY" not in result
        assert "END RSA PRIVATE KEY" not in result
        assert "[REDACTED: credential]" in result
        assert warnings

    def test_redacts_truncated_private_key_body(self) -> None:
        """A key block missing the END marker still has its body redacted."""
        body = "MIIEpAIBAAKCAQEAtruncatedbodybytes1234567890abcdef"
        text = f"-----BEGIN EC PRIVATE KEY-----\n{body}"
        result, _ = redact_credentials(text)
        assert body not in result
        assert "BEGIN EC PRIVATE KEY" not in result

    def test_redacts_encrypted_private_key_body(self) -> None:
        """Encrypted PEM: Proc-Type/DEK-Info headers carry ':'/',' — body must
        still be fully redacted (a base64-only body class would stop short)."""
        body = "MIIEpAIBAAKCAQEAencryptedbodybytes0987654321zyxwvu"
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "Proc-Type: 4,ENCRYPTED\n"
            "DEK-Info: AES-128-CBC,DDEA6208BB09B295E4C9BA85D2E85CD1\n\n"
            f"{body}\n"
            "-----END RSA PRIVATE KEY-----"
        )
        result, _ = redact_credentials(text)
        assert body not in result
        assert "DEK-Info" not in result
        assert "BEGIN RSA PRIVATE KEY" not in result

    def test_redacts_two_private_key_blocks(self) -> None:
        """Two adjacent key blocks: each body redacted, intervening prose kept."""
        body1 = "MIIEpAIBAAKCAQEAfirstkeybody1234567890abcdefghij"
        body2 = "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAA"
        text = (
            f"-----BEGIN RSA PRIVATE KEY-----\n{body1}\n-----END RSA PRIVATE KEY-----\n"
            "middle prose stays\n"
            f"-----BEGIN OPENSSH PRIVATE KEY-----\n{body2}\n-----END OPENSSH PRIVATE KEY-----"
        )
        result, _ = redact_credentials(text)
        assert body1 not in result
        assert body2 not in result
        assert "middle prose stays" in result

    def test_private_key_prose_not_over_redacted(self) -> None:
        """A full key block followed by prose: the END anchor stops the span so
        the trailing prose is preserved (no over-redaction)."""
        body = "MIIEpAIBAAKCAQEAbodybytes1234567890abcdefghijklmn"
        text = (
            f"-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n"
            "Contact ops@example.com if this key is expired."
        )
        result, _ = redact_credentials(text)
        assert body not in result
        assert "Contact ops@example.com if this key is expired." in result

    def test_no_false_positive_on_private_key_prose(self) -> None:
        """Prose mentioning 'PRIVATE KEY' without the PEM markers is untouched."""
        text = "See the PRIVATE KEY handling section of the runbook."
        result, warnings = redact_credentials(text)
        assert result == text
        assert not warnings

    def test_pem_header_in_prose_without_end_keeps_trailing_lines(self) -> None:
        """A PEM BEGIN header mentioned inline in prose (no body, no END marker)
        must not swallow trailing lines to end-of-string. Guards the `$`
        end-of-string over-redaction regression (security-review 05687e60)."""
        text = (
            "For example, a PEM key starts with "
            "-----BEGIN RSA PRIVATE KEY----- and contains base64 data.\n"
            "Line 2 of docs.\n"
            "Line 3."
        )
        result, _ = redact_credentials(text)
        assert "Line 2 of docs." in result
        assert "Line 3." in result
        assert "and contains base64 data." in result

    def test_redacts_encrypted_private_key_across_dek_info_blank_line(self) -> None:
        """RFC 1421 ENCRYPTED PEM (no END): the mandatory blank line between the
        DEK-Info header and the base64 body must NOT terminate the run — the
        whole body is redacted. Guards the round-3 leak where a
        single blank line ended the continuation and emitted the body verbatim."""
        body_line1 = "MIIEpQIBAAKCAQEAencryptedbodybytesABCDEF1234567890zyxwv"
        body_line2 = "secondencryptedbodylineGHIJKL0987654321mnopqrABCDEF"
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "Proc-Type: 4,ENCRYPTED\n"
            "DEK-Info: DES-EDE3-CBC,ABCD1234EF567890\n"
            "\n"
            f"{body_line1}\n"
            f"{body_line2}"
        )
        result, _ = redact_credentials(text)
        assert body_line1 not in result
        assert body_line2 not in result
        assert "DEK-Info" not in result
        assert "BEGIN RSA PRIVATE KEY" not in result

    def test_two_blank_lines_terminate_private_key_run(self) -> None:
        """TWO+ consecutive blank lines terminate the truncated-key run so
        trailing prose is preserved (no over-redaction). The single-blank-line
        lookahead must not extend across a paragraph break."""
        body = "MIIEpQIBAAKCAQEAbodybytes1234567890abcdefghijklmnop"
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            f"{body}\n"
            "\n"
            "\n"
            "ThisProseAfterTwoBlankLinesMustSurvive and stay intact."
        )
        result, _ = redact_credentials(text)
        assert body not in result
        assert "ThisProseAfterTwoBlankLinesMustSurvive and stay intact." in result

    def test_redacts_slack_token(self) -> None:
        text = "Token is xoxb-1234567890-abcdefghij"
        result, _ = redact_credentials(text)
        assert "xoxb-" not in result

    # ── Third-party developer credentials (pentest issue 2) ──

    # NOTE: each fixture below is written as two adjacent string literals that
    # Python concatenates at parse time, so the runtime secret value is exactly
    # the intended token (the redaction test is unchanged). The split keeps any
    # single source literal from being a complete provider token, so GitHub
    # push-protection / secret scanners don't flag these synthetic fixtures.
    #
    # The explicit ``ids=`` labels exist for the same reason one level up:
    # without them pytest derives each test ID from the REASSEMBLED value, and
    # the full key-shaped string then lands verbatim in every derived artifact
    # (.test_durations, junit XML, CI logs). Push protection rejects any branch
    # carrying such an artifact — that is what kept the Update Test Durations
    # workflow from ever landing its PR. Keep these labels secret-shape-free.
    @pytest.mark.parametrize(
        "secret",
        [
            "ghp_" "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12",  # GitHub classic PAT
            "gho_" "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef1234",  # GitHub OAuth
            "github_pat_"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij1234567890ABCDEFGHIJ",  # fine-grained
            "glpat-" "xxxx1234xxxx5678xxxx",  # GitLab PAT
            "sk_live_" "51HG7aBcDeFgHiJkLmNoPqRsTuVwXyZ",  # Stripe live
            "sk_test_" "51HG7aBcDeFgHiJkLmNoPqRsTuVwXyZ",  # Stripe test
            "rk_live_" "51HG7aBcDeFgHiJkLmNoPqRsTuVwXyZ",  # Stripe restricted
            "SG." "abcdefghijklmnop.qrstuvwxyz1234567890ABCDEFGHIJKLMNOPQR",  # SendGrid
            "sk-proj-" "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234",  # OpenAI
            "sk-ant-api03-" "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP",  # Anthropic
            "npm_" "abcdefghijklmnopqrstuvwxyz123456",  # npm
            "pypi-" "AgEIcHlwaS5vcmcCJGI2YzRlYjYwLWExYmUtNDgxZi04",  # PyPI
            "dop_v1_" "abcdefghijklmnopqrstuvwxyz1234567890abcdefghijklmnopqrst",  # DigitalOcean
            "GOCSPX-" "abcdefghijklmnopqrstuvwx",  # Google OAuth
        ],
        ids=[
            "github-classic-pat",
            "github-oauth",
            "github-fine-grained-pat",
            "gitlab-pat",
            "stripe-live",
            "stripe-test",
            "stripe-restricted",
            "sendgrid",
            "openai-project",
            "anthropic",
            "npm-token",
            "pypi-token",
            "digitalocean",
            "google-oauth",
        ],
    )
    def test_redacts_third_party_credentials(self, secret: str) -> None:
        text = f"KEY={secret}"
        result, warnings = redact_credentials(text)
        assert secret not in result
        assert "[REDACTED: credential]" in result
        assert len(warnings) == 1

    @pytest.mark.parametrize(
        "secret",
        [
            "ghp_" "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12",  # GitHub classic PAT
            "sk-ant-api03-" "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP",  # Anthropic
            "sk-proj-" "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234",  # OpenAI
            "sk_live_" "51HG7aBcDeFgHiJkLmNoPqRsTuVwXyZ",  # Stripe live
            "xoxb-" "1234567890-abcdefghijklmnop",  # Slack bot token
        ],
        # Safe display labels: pytest would otherwise derive the ID from the
        # reassembled token — see the note on the parametrize above.
        ids=["github-classic-pat", "anthropic", "openai-project", "stripe-live", "slack-bot"],
    )
    def test_warning_does_not_leak_secret_prefix(self, secret: str) -> None:
        """The warnings list must carry NO secret bytes — only length metadata.

        The bug this guards: the plaintext branch
        emitted ``matched[:20]``, leaking a 12-16 char slice of the real secret
        (a fingerprint of exactly which key matched) into a list that sinks
        expect to be safe to log/surface. High-entropy API-key prefixes
        (``ghp_``, ``sk-ant-``, ``sk-proj-``, ``sk_live_``, ``xoxb-``) are the
        worst case; assert none of the raw secret survives in any warning.
        """
        text = f"KEY={secret}"
        _, warnings = redact_credentials(text)
        assert len(warnings) == 1
        joined = " ".join(warnings)
        # The full secret must not appear, and neither may any leading slice of
        # it beyond the (non-secret) provider prefix — assert the whole value
        # and its first 20 chars (the old leak window) are both absent.
        assert secret not in joined
        assert secret[:20] not in joined
        # Positive: the warning still reports the redaction with a length.
        assert "Redacted credential pattern" in joined
        assert f"{len(secret)} chars" in joined

    def test_redacts_db_uri_with_embedded_password(self) -> None:
        text = "DATABASE_URL=postgres://admin:SuperSecret123@db.example.com:5432/prod"
        result, _ = redact_credentials(text)
        assert "SuperSecret123" not in result
        assert "admin" not in result
        # host after @ may remain — only the credential prefix is redacted
        assert "[REDACTED: credential]" in result

    def test_every_redaction_tag_constant_is_registered(self) -> None:
        """A new credential tag must be added to ``CREDENTIAL_REDACTION_TAGS``.

        Consumers ask that tuple "did the redactor replace something here" -- the
        dashboard chat notice counts it to tell the user their text
        was rewritten. A tag that exists but is not registered is invisible to
        every such consumer, which is exactly how the encoded-credential tag came
        to be missed. This ratchet makes that omission fail here instead of
        silently degrading a user-facing warning.
        """
        from kiro_crew.security import redaction

        declared = {
            name: value
            for name, value in vars(redaction).items()
            if name.startswith("_REDACTED_") and name.endswith("_TAG")
            if isinstance(value, str)
        }
        assert declared, "tag-constant naming changed; this ratchet no longer sees them"

        unregistered = {
            name: value
            for name, value in declared.items()
            if value not in redaction.CREDENTIAL_REDACTION_TAGS
        }
        assert not unregistered, (
            "redaction tag(s) not in CREDENTIAL_REDACTION_TAGS: "
            f"{sorted(unregistered)} -- add them there so consumers that ask "
            "'was anything redacted' (e.g. the dashboard chat notice) can see them"
        )

    def test_pass_two_emits_a_registered_tag(self) -> None:
        """The base64 pass must substitute a tag consumers actually look for."""
        import base64

        from kiro_crew.security import (
            _REDACTED_ENCODED_CREDENTIAL_TAG,
            CREDENTIAL_REDACTION_TAGS,
        )

        blob = base64.b64encode(b"postgresql://user:pass@host:5432/db").decode()
        result, warnings = redact_credentials(f"blob: {blob}")

        assert _REDACTED_ENCODED_CREDENTIAL_TAG in result
        assert _REDACTED_ENCODED_CREDENTIAL_TAG in CREDENTIAL_REDACTION_TAGS
        assert any("base64-encoded" in w for w in warnings)

    @pytest.mark.parametrize(
        "mongo",
        [
            "mongodb://user:p%40ss@cluster0.example.com",
            "mongodb+srv://user:pw@cluster0.example.com",
            "mysql://root:toor@localhost:3306/db",
            "redis://default:secret@redis.example.com:6379",
            # URL userinfo is a credential on fetch schemes too (a
            # token-bearing artifact CDN base quoted by update-failure text).
            "https://user:tok-SECRET99@cdn.example.com/w.whl",
            "ftp://anon:pw@mirror.example.com/f",
            # A password containing an unencoded @ must redact through the
            # FINAL authority separator, not stop at the first @.
            "https://user:p@ss@cdn.example.com/w.whl",
            "redis://default:se@cret@redis.example.com:6379",
        ],
    )
    def test_redacts_various_db_uris(self, mongo: str) -> None:
        result, _ = redact_credentials(mongo)
        assert "[REDACTED: credential]" in result

    def test_no_false_positive_on_benign_strings(self) -> None:
        """Non-credential strings that superficially resemble prefixes stay intact."""
        for benign in [
            "npm_config_cache=/home/u/.npm",  # npm_ env var, too short + underscores
            "git sha 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b",  # 40-hex git SHA
            "postgresql://localhost:5432/db",  # no user:pass@
            "https://example.com:8080/path",  # port is not userinfo
            "https://example.com/a@b",  # @ in the path, not the authority
            "SG.short.x",  # segments too short
            "the ghp_ prefix on its own",  # no token body
        ]:
            result, warnings = redact_credentials(benign)
            assert result == benign, f"false positive on {benign!r}"
            assert warnings == []

    def test_bare_hex_not_redacted_by_design(self) -> None:
        """A bare 32-hex token (e.g. Twilio) is intentionally NOT redacted.

        A generic 32-hex string collides with MD5 hashes, git object ids, and
        dash-less UUIDs, so redacting it would be high false-positive. Matches
        the pentest recommendation, which omitted Twilio from the pattern set.
        """
        text = "TWILIO_AUTH=a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
        result, _ = redact_credentials(text)
        assert result == text

    def test_preserves_normal_text(self) -> None:
        text = "The deployment succeeded. 42 pods running."
        result, warnings = redact_credentials(text)
        assert result == text
        assert len(warnings) == 0

    def test_preserves_aws_cli_output(self) -> None:
        text = '{"Account": "123456789012", "Arn": "arn:aws:iam::123:user/dev"}'
        result, warnings = redact_credentials(text)
        assert result == text
        assert len(warnings) == 0

    def test_preserves_ada_update_success(self) -> None:
        text = "Successfully refreshed aws credentials for default"
        result, warnings = redact_credentials(text)
        assert result == text
        assert len(warnings) == 0

    def test_preserves_git_output(self) -> None:
        text = "Cloning into 'KiroCrew'...\nremote: Enumerating objects: 1234"
        result, warnings = redact_credentials(text)
        assert result == text

    def test_preserves_kubectl_output(self) -> None:
        text = "NAME       READY   STATUS    RESTARTS   AGE\nnginx-pod  1/1     Running   0          5m"
        result, warnings = redact_credentials(text)
        assert result == text

    # ── JSON-form credential redaction (regression) ──
    # The key-value patterns required the key name to be immediately followed by
    # `[:=]`, so JSON (`"aws_secret_access_key": "..."`) — where a closing quote
    # sits between the key and the colon — was NOT matched and the secret leaked.
    # JSON is one of the most common shapes credentials take in tool output/logs.

    def test_redacts_json_secret_access_key(self) -> None:
        text = '{"aws_secret_access_key": "ABCverysecret123"}'
        result, warnings = redact_credentials(text)
        assert "ABCverysecret123" not in result
        assert warnings

    def test_redacts_json_secret_no_space(self) -> None:
        text = '{"aws_secret_access_key":"ABCverysecret123"}'
        result, _ = redact_credentials(text)
        assert "ABCverysecret123" not in result

    def test_redacts_json_session_token(self) -> None:
        text = '{"aws_session_token": "XYZtokenvalue789"}'
        result, _ = redact_credentials(text)
        assert "XYZtokenvalue789" not in result

    def test_redacts_json_access_key_id(self) -> None:
        text = '{"aws_access_key_id": "someAccessKeyIdValue"}'
        result, _ = redact_credentials(text)
        assert "someAccessKeyIdValue" not in result

    def test_bare_keyvalue_still_redacted(self) -> None:
        # Regression guard: the original bare forms must still work.
        for text, secret in [
            ("aws_secret_access_key=BAREsecret1", "BAREsecret1"),
            ("aws_secret_access_key: BAREsecret2", "BAREsecret2"),
            ("SecretAccessKey=BAREsecret3", "BAREsecret3"),
        ]:
            result, _ = redact_credentials(text)
            assert secret not in result, f"bare form leaked: {text!r}"

    def test_prose_mentioning_key_not_overredacted(self) -> None:
        # The key name as ordinary prose (followed by a space/word, not [:=]) must
        # not trigger redaction — guards against over-redaction from the new pattern.
        text = "The aws_secret_access_key field is required for auth."
        result, _ = redact_credentials(text)
        assert result == text

    def test_redacts_json_compact_no_overcapture(self) -> None:
        """Compact JSON: only the secret value is redacted, not adjacent fields."""
        text = '{"aws_secret_access_key":"SECRET","region":"us-east-1"}'
        result, _ = redact_credentials(text)
        assert "SECRET" not in result
        assert '"region":"us-east-1"' in result  # adjacent field preserved

    def test_multi_credential_json_both_redacted(self) -> None:
        """Multiple credentials in one compact JSON object — both must be redacted."""
        text = '{"aws_secret_access_key":"SECRET1","aws_session_token":"TOKEN2","region":"x"}'
        result, _ = redact_credentials(text)
        assert "SECRET1" not in result
        assert "TOKEN2" not in result
        assert '"region":"x"' in result

    # ── JWT / Authorization: Bearer tokens (security-review cc1d6bdd) ──
    # JWTs and OAuth bearer tokens can leak in tool output / logs. They are
    # redacted here. `eyJ` is the base64url of every JWT header's `{"` prefix.

    _JWT = security_helpers._JWT

    def test_redacts_jwt(self) -> None:
        text = f"token={self._JWT}"
        result, warnings = redact_credentials(text)
        assert self._JWT not in result
        assert "[REDACTED: credential]" in result
        assert len(warnings) == 1

    def test_redacts_jwt_in_prose(self) -> None:
        text = f"Here is the id_token: {self._JWT} — do not log it."
        result, _ = redact_credentials(text)
        assert "eyJhbGci" not in result
        assert "do not log it." in result  # trailing prose preserved (no over-capture)

    # A JWE (RFC 7516) is a five-segment compact-serialization token
    # (header.encrypted_key.iv.ciphertext.tag). The three-segment JWT pattern
    # would only redact the first three segments and leak the ciphertext + tag,
    # so the segment quantifier accepts 5-segment tokens as a whole.
    _JWE = (
        "eyJhbGciOiJSU0EtT0FFUCIsImVuYyI6IkExMjhHQ00ifQ"
        ".OKOawDo13gRp2ojaHV7LFpZcgV7T6DVZKTyKOMTYUmKoTCVJRgckCL9kiMT03JGe"
        ".48V1_ALb6US04U3b"
        ".5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji"
        ".XFBoMYUZodetZdvTiFvSkQ"
    )

    def test_redacts_jwe_five_segments(self) -> None:
        """A 5-segment JWE must redact as one token, not leak ciphertext+tag."""
        text = f"token={self._JWE}"
        result, warnings = redact_credentials(text)
        assert self._JWE not in result
        assert "XFBoMYUZodetZdvTiFvSkQ" not in result  # trailing tag segment gone
        assert "[REDACTED: credential]" in result
        assert len(warnings) == 1

    # RFC 7516 compact JWE with direct (`alg:dir`) or key-agreement (`ECDH-ES`)
    # key management: the Encrypted Key (2nd) segment is EMPTY, giving two
    # consecutive dots -> `header..iv.ciphertext.tag`. A `+` quantifier on the
    # post-header segments would fail to match this and leak ciphertext + tag.
    _JWE_DIR = security_helpers._JWE_DIR

    def test_the_jose_samples_are_the_shared_helpers_objects(self) -> None:
        """``TestStreamRedactor`` reads these two samples from ``security_helpers``.

        Binding the same objects here keeps one copy of each token for both modules.
        """
        assert TestRedactCredentials._JWT is security_helpers._JWT
        assert TestRedactCredentials._JWE_DIR is security_helpers._JWE_DIR

    def test_redacts_jwe_direct_empty_key_segment(self) -> None:
        """A dir/ECDH-ES JWE (empty 2nd segment) must redact whole, not leak."""
        text = f"token={self._JWE_DIR}"
        result, warnings = redact_credentials(text)
        assert self._JWE_DIR not in result
        assert "XFBoMYUZodetZdvTiFvSkQ" not in result  # trailing tag segment gone
        assert "5eym8TW_c8SuK0ltJ3rpYIzOeDQz7TALvtu6UG9oMo4vpzs9tX_EFShS8iB7j6ji" not in result
        assert "[REDACTED: credential]" in result
        assert len(warnings) == 1

    def test_redacts_authorization_bearer(self) -> None:
        text = "Authorization: Bearer abc123.def-456_ghi/jkl+mno=="
        result, warnings = redact_credentials(text)
        assert "abc123.def-456_ghi/jkl+mno==" not in result
        assert "[REDACTED: credential]" in result
        assert len(warnings) == 1

    def test_redacts_json_shaped_authorization_bearer(self) -> None:
        """A serialized JSON header `{"Authorization": "Bearer <tok>"}` redacts.

        The quote before the `:` and
        the quote before the token defeated the old `Authorization:\\s*Bearer`
        prefix, leaking the token in structured logs / JSON request dumps.
        """
        text = '{"Authorization": "Bearer abc123.def-456_ghi/jkl+mno=="}'
        result, warnings = redact_credentials(text)
        assert "abc123.def-456_ghi/jkl+mno==" not in result
        assert "[REDACTED: credential]" in result
        assert len(warnings) == 1

    def test_redacts_authorization_bearer_no_space(self) -> None:
        text = "Authorization:Bearer   opaque-token-value"
        result, _ = redact_credentials(text)
        assert "opaque-token-value" not in result

    def test_redacts_lowercase_authorization_bearer(self) -> None:
        """HTTP/2 + requests/net/http logs emit a lowercase header/scheme.

        Header names are case-insensitive (RFC 7230 §3.2), HTTP/2 mandates
        lowercase, and the `Bearer` scheme is case-insensitive (RFC 6750 §2.1),
        so the case-sensitive prefix would otherwise leak the token.
        """
        text = "authorization: bearer opaque-token-value"
        result, warnings = redact_credentials(text)
        assert "opaque-token-value" not in result
        assert "[REDACTED: credential]" in result
        assert len(warnings) == 1

    def test_redacts_bearer_jwt_single_match(self) -> None:
        """A Bearer header carrying a JWT redacts as one match, not two."""
        text = f"Authorization: Bearer {self._JWT}"
        result, warnings = redact_credentials(text)
        assert self._JWT not in result
        assert "Bearer" not in result
        assert len(warnings) == 1

    def test_jwt_prefix_without_structure_not_redacted(self) -> None:
        """A bare `eyJ` token with no `.`-separated segments must not over-redact."""
        text = "The variable eyJson holds parsed JSON output."
        result, warnings = redact_credentials(text)
        assert result == text
        assert warnings == []

    def test_hostname_containing_eyj_not_redacted(self) -> None:
        """A dotted name with `eyJ` inside has JWT shape but no JSON-object header."""
        from kiro_crew.security import _contains_fixed_credential, _decode_b64_safe

        for text in ("ssh honeyJar.example.com", "https://api.honeyJar.co.uk/v1/x"):
            assert redact_credentials(text) == (text, []), text
            assert not _contains_fixed_credential(text), text
            assert _decode_b64_safe(base64.b64encode(text.encode()).decode()) == "", text

    def test_jose_validated_jwt_redacted_on_every_batch_path(self) -> None:
        from kiro_crew.security import (
            _contains_fixed_credential,
            _decode_b64_chunk,
            _decode_b64_safe,
        )

        for token in (self._JWT, self._JWE, self._JWE_DIR):
            text = f"host honeyJar.example.com token {token}"
            result, warnings = redact_credentials(text)
            assert result == "host honeyJar.example.com token [REDACTED: credential]"
            assert len(warnings) == 1
            assert _contains_fixed_credential(token)
            encoded = base64.b64encode(token.encode()).decode()
            assert _decode_b64_chunk(encoded) == token
            assert _decode_b64_safe(encoded) == token

    def test_credential_inside_rejected_jwt_shape_still_redacted(self) -> None:
        """A rejected JWT-shaped span is rescanned, so nothing inside it leaks."""
        result, _ = redact_credentials("eyJx.AKIAIOSFODNN7EXAMPLE.y")
        assert "AKIAIOSFODNN7EXAMPLE" not in result
        result, _ = redact_credentials(f"eyJfoo.{self._JWT}")
        assert result == "eyJfoo.[REDACTED: credential]"
        # a link token matched by the same start: the other branches are retried there
        link = "eyJ" + "e" * 100 + "." + "S" * 43
        assert redact_credentials(f"{link}.json")[0] == "[REDACTED: credential].json"

    def test_non_jose_json_header_still_redacted(self) -> None:
        """itsdangerous / Flask-session tokens carry a JSON header with no `alg`/`enc`."""
        typ_only = base64.urlsafe_b64encode(b'{"typ":"JWT"}').decode().rstrip("=")
        payload = base64.urlsafe_b64encode(b'{"user_id":7}').decode().rstrip("=")
        for token in (f"{typ_only}.payload.sig", f"{payload}.ZsT9kA.sig-x_Y"):
            assert redact_credentials(f"cookie {token} end")[0] == (
                "cookie [REDACTED: credential] end"
            ), token

    def test_dense_eyj_header_fails_closed(self) -> None:
        """A header holding a second `eyJ` is redacted whole instead of rescanned per `eyJ`."""
        from kiro_crew.security import _partial_jwt_tail

        dense = "eyJ" * 30000 + ".x.y"
        assert redact_credentials(dense)[0] == "[REDACTED: credential]"
        assert redact_credentials(f"monkeyJ{self._JWT}")[0] == "monk[REDACTED: credential]"
        assert _partial_jwt_tail(dense).start() == 0

    # ── Two-segment dashboard link token ──
    # `dashboard.token_auth.generate_token` emits `base64url(payload).base64url(
    # hmac_sig)` — TWO segments, so the JWT alternative's old `{2,4}` segment
    # floor never matched it. The token then fell through to the bare-secret
    # entropy pass, whose run class is STANDARD base64 (`[A-Za-z0-9+/]`) and
    # excludes base64url's `-`/`_`. Redaction therefore depended on which
    # characters a random signature happened to contain.

    # Same payload; signatures differ only in whether they contain a `-`.
    _LINK_PAYLOAD = (
        "eyJzdWIiOiJsb2NhbC1hcHAiLCJleHAiOjE3ODU0MTc2MDYsInNlc3Npb25fZXhwIjoxNzg1NDg5MzA2"
        "LCJpYXQiOjE3ODU0MTczMDYsIm5vbmNlIjoiOTM5YzE3MGQ5ZjBiNmEyMiIsImdlbiI6MH0"
    )
    _SIG_PLAIN = "gVhM4aKLA8dyFHoZlQx6SpYSNPkXA07kpDhWd6UhZIa"  # no `-`/`_`
    _SIG_URLSAFE = "gVhM4aKLA8dyFH-oZlQx6SpYSNPkXA07kpDhWd6UhZI"  # contains `-`

    def test_redacts_two_segment_dashboard_link_token(self) -> None:
        """The whole two-segment token is replaced, not just its signature."""
        token = f"{self._LINK_PAYLOAD}.{self._SIG_URLSAFE}"
        text = f"https://host.example.com/?token={token}"
        result, warnings = redact_credentials(text)
        assert result == "https://host.example.com/?token=[REDACTED: credential]"
        # The payload segment carries the claims (sub/exp/nonce) and must not
        # survive: a partially-redacted token still looks like a usable URL.
        assert "eyJzdWIi" not in result
        assert len(warnings) == 1

    def test_two_segment_token_redaction_independent_of_signature_alphabet(self) -> None:
        """Redaction must not depend on `-`/`_` appearing in the signature.

        Before the dedicated two-segment alternative, only signatures free of
        base64url's `-`/`_` formed a 40+ run for the bare-secret pass, so
        `(62/64)^42` = 26.4% of minted tokens were partially redacted and the
        remaining ~74% streamed out verbatim.
        """
        for sig in (self._SIG_PLAIN, self._SIG_URLSAFE):
            token = f"{self._LINK_PAYLOAD}.{sig}"
            result, warnings = redact_credentials(f"?token={token}")
            assert result == "?token=[REDACTED: credential]", sig
            assert len(warnings) == 1, sig

    def test_identifier_containing_eyj_not_redacted(self) -> None:
        """An `eyJ`-containing identifier followed by attribute access is code.

        The two-segment alternative needs a left boundary. Without one, the
        substring `eyJson.get` inside `keyJson.get` matches and the line is
        rewritten to `k[REDACTED: credential](raw)`. `redact_credentials` feeds
        persisted diff bodies, saved artifacts and compressed history, so a false
        positive is written to disk with no way to recover the original.
        """
        for text in (
            "keyJson.get(raw)",
            "surveyJson.title",
            "serviceAccountKeyJson.load(path)",
            "monkeyJson.dumps(x)",
        ):
            result, warnings = redact_credentials(text)
            assert result == text, text
            assert warnings == [], text

    def test_short_two_segment_base64url_not_redacted(self) -> None:
        """A short `eyJ…` value with one dot is a filename or a quoted claim set.

        The per-segment length floors carry this: `eyJ2IjoxfQ` is 7 chars past the
        prefix (far under the 40-char payload floor) and `json` is under the 20-char
        signature floor. A real link token clears both by a wide margin.
        """
        for text in (
            "cache file eyJ2IjoxfQ.json written",
            "See https://example.com/path?q=eyJhbGciOiJIUzI1NiJ9.",
        ):
            result, warnings = redact_credentials(text)
            assert result == text, text
            assert warnings == [], text

    def test_boundary_position_identifier_not_redacted(self) -> None:
        """A dotted identifier that BEGINS with `eyJ` must survive.

        The left boundary cannot help at offset 0, and a length FLOOR alone is
        beatable by a verbose enough identifier, so the segment lengths are taken
        from the generator instead: exactly 43 chars of HMAC signature, and a payload
        floor no real identifier reaches. Without that, these collapse to
        `[REDACTED: credential](x)` inside a persisted diff chip body.
        """
        for text in (
            "eyJsonSerializer.deserializeFromStringValue(x)",
            "eyJsonDocument.deserializeConfiguration(raw)",
            "obj.eyJsonReader.readValueFromInputStream(x)",
            "eyJargonized.intercontinentalization",
            # exactly 40 chars past `eyJ`, which cleared an earlier `{40,}` floor
            "eyJsonSerializerConfigurationFactoryBuilder.deserializeFromStringValue(x)",
            # long enough to clear any plausible payload floor on the first component
            "eyJsonSerializerConfigurationFactoryBuilderRegistryProviderDelegating"
            "InterceptorFactoryAdapterHandler.deserializeFromStringValueUsing"
            "ConfiguredObjectMapperInstance(x)",
        ):
            result, warnings = redact_credentials(text)
            assert result == text, text
            assert warnings == [], text

    def test_link_token_signature_is_43_chars(self) -> None:
        """Pin the assumption the 2-segment alternative encodes as `{43}`.

        `token_auth._sign` is HMAC-SHA256 base64url-unpadded, so the signature is
        always exactly 43 chars. The redaction pattern hard-codes that width. If the
        digest ever changes, this fails loudly here rather than silently disabling
        redaction of the link token in production.
        """
        from kiro_crew.dashboard.token_auth import _sign

        for payload in (b'{"sub":"x"}', b"", b"a" * 4096):
            assert len(_sign(payload)) == 43, payload[:16]

    def test_link_token_payload_clears_the_96_char_floor(self) -> None:
        """Pin the `{96,}` payload floor against the generator's own claim set.

        The floor must stay BELOW the shortest payload a mint can produce, or the
        pattern silently stops matching live tokens. That is a leak, not a
        cosmetic miss, so it is pinned rather than asserted in a comment.

        Both the floor and the claim set are read from source instead of restated
        here: the floor comes from the compiled pattern, and the claim KEYS come
        from a real mint, so dropping a claim or raising the floor fails loudly.
        """
        import re

        from kiro_crew.dashboard.token_auth import generate_token
        from kiro_crew.security import _CREDENTIAL_PATTERNS

        floors = re.findall(r"eyJ\[A-Za-z0-9_-\]\{(\d+),\}", _CREDENTIAL_PATTERNS.pattern)
        assert len(floors) == 1, f"expected one bounded eyJ floor, got {floors}"
        floor = int(floors[0])

        payload = generate_token("local-app", 300, register_nonce=False).split(".")[0]
        assert payload.startswith("eyJ")
        assert len(payload) - 3 > floor, "a real mint no longer clears the floor"

        # Derived worst case: the narrowest `sub` a caller could pass, with every
        # float claim at its shortest repr (an exactly-integral `time.time()`).
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        # `gen` is normalised alongside `sub` because it mirrors the persisted
        # counter behind `revocation_gen.current_revocation_gen()`, LOADED FROM
        # DISK on first use. Left ambient, the
        # derived floor would depend on how many times this machine has revoked:
        # the repr widens at 10, moving the floor 145 -> 147, so the pin below would
        # fail on a clean checkout with no code change.
        shortest = {"sub": "x", "gen": 0}
        minimal = {
            k: shortest.get(k, 1785543020.0 if isinstance(v, float) else v)
            for k, v in claims.items()
        }
        raw = json.dumps(minimal, separators=(",", ":")).encode()
        worst = len(base64.urlsafe_b64encode(raw).decode().rstrip("=")) - 3
        assert worst > floor, f"derived floor {worst} no longer clears {{{floor},}}"
        # Pinned so the figure quoted in `security.py` cannot rot silently.
        assert worst == 145, f"derived floor moved to {worst}; update security.py"

    def test_bearer_word_alone_not_redacted(self) -> None:
        """The word `Bearer` without the `Authorization:` header prefix is prose."""
        text = "The bond is a bearer instrument, not registered."
        result, warnings = redact_credentials(text)
        assert result == text
        assert warnings == []


class TestTokenParamValueRedaction:
    """Pass 4: the VALUE of a `?token=` / `&token=` URL parameter.

    Keyed on the parameter NAME, not the value's shape, so an OPAQUE bearer
    value -- one that looks nothing like a JWT -- is redacted where every
    shape-based pass sees ordinary text. `token=` stays visible so a redacted
    URL still reads as a token URL. The pass is deliberately absent from
    `_contains_fixed_credential`, so the request-blocking surface in
    `exfil.py` is unchanged.
    """

    # Opaque: mixed-case alphanumerics, no `eyJ` prefix, far under the 40-char
    # bare-secret floor -- invisible to every shape-based pass. An `eyJ`-shaped
    # value here would make this pass look tested when it is not.
    _OPAQUE = "Xk9fQ2mP4nR7sT1v"

    def test_opaque_value_is_redacted(self) -> None:
        """An opaque non-`eyJ` value in a token URL must not survive."""
        text = f"open https://host.example.com/?token={self._OPAQUE} to continue"
        result, warnings = redact_credentials(text)
        assert self._OPAQUE not in result
        assert result == ("open https://host.example.com/?token=[REDACTED: credential] to continue")
        assert warnings == ["Redacted token parameter value (16 chars)"]

    def test_ampersand_form_and_neighbour_params_survive(self) -> None:
        text = f"https://h.example/x?a=1&token={self._OPAQUE}&b=2"
        result, _ = redact_credentials(text)
        assert result == "https://h.example/x?a=1&token=[REDACTED: credential]&b=2"

    def test_template_placeholder_dollar_is_not_redacted(self) -> None:
        """A JS/TS `${...}` placeholder after `token=` is code, not a value."""
        for text in (
            "const url = `${base}&token=${encodeURIComponent(jwt)}`;",
            "https://h.example/x?token=${x}",
        ):
            result, warnings = redact_credentials(text)
            assert result == text, text
            assert warnings == [], text

    def test_dollar_values_without_placeholder_still_redact(self) -> None:
        """Only `${` is exempt: a `$`-led value or a lone trailing `$` is redacted."""
        for value in ("$abc", "$"):
            for tail in ("", "&b=2"):
                result, warnings = redact_credentials(f"https://h/x?token={value}{tail}")
                assert result == f"https://h/x?token=[REDACTED: credential]{tail}", (value, tail)
                assert warnings == [f"Redacted token parameter value ({len(value)} chars)"]

    def test_value_before_brace_still_redacts(self) -> None:
        result, warnings = redact_credentials("https://h/x?token=abc${x}")
        assert result == "https://h/x?token=[REDACTED: credential]{x}"
        assert warnings == ["Redacted token parameter value (4 chars)"]

    def test_stream_floor_cut_keeps_a_placeholder_whole(self) -> None:
        """A forced 512-char floor cut never splits `$` from `{`: stream equals batch."""
        from kiro_crew.security import StreamRedactor

        for size in range(480, 501):
            text = " &token=${" + "a" * size + " BEGIN RSA PRIVATE"
            redactor = StreamRedactor()
            streamed = redactor.feed(text) + redactor.flush()
            assert streamed == redact_credentials(text)[0], size

    def test_stream_matches_batch_at_every_chunk_cut_near_a_placeholder(self) -> None:
        from kiro_crew.security import StreamRedactor

        for text in (
            "x &token=${jwt} y",
            "x ?token=abc${x} y",
            " &token=${" + "a" * 490 + " BEGIN RSA PRIVATE",
        ):
            expected = redact_credentials(text)[0]
            at = text.index("${")
            for cut in range(max(0, at - 12), min(len(text), at + 12) + 1):
                redactor = StreamRedactor()
                streamed = redactor.feed(text[:cut]) + redactor.feed(text[cut:]) + redactor.flush()
                assert streamed == expected, (text[:20], cut)

    def test_entity_equals_does_not_capture_its_own_semicolon(self) -> None:
        """A present `;` is the reference's terminator, never the value.

        Red before the fix: the greedy EQ gave up its `;` to the value class,
        so pass 4 spliced the tag over the semicolon -- corrupting text
        `chat_runner.py` redacts IN PLACE with no recovery path.
        """
        for anchor in ("?token&#61;", "?token&#x3D;", "?token&#0000061;", "&token&#61;"):
            for tail in ("", "&x=1", "#frag", " tail"):
                text = f"https://h/p{anchor}{tail}"
                result, warnings = redact_credentials(text)
                assert result == text, (anchor, tail)  # corruption assertion
                assert ";" not in result or result.count(";") == text.count(";")
                assert warnings == [], (anchor, tail)

    def test_empty_entity_equals_value_matches_the_plain_equals_baseline(self) -> None:
        """`?token&#61;` with no value behaves exactly like `?token=` with no value."""
        for entity in ("&#61;", "&#x3D;", "&#0000061;", "&equals;"):
            for tail in ("", "&x=1"):
                assert redact_credentials(f"?token{entity}{tail}")[0] == f"?token{entity}{tail}"
                assert redact_credentials(f"?token={tail}")[0] == f"?token={tail}"

    def test_semicolon_led_value_is_still_redacted(self) -> None:
        """Still-green positive: a `;` AFTER the terminator is value, not structure."""
        for anchor in ("?token&#61;", "?token&#x3D;", "?token=", "?token&#0000061;"):
            result, warnings = redact_credentials(f"{anchor};{self._OPAQUE}")
            assert result == f"{anchor}[REDACTED: credential]"
            assert warnings == [f"Redacted token parameter value ({len(';' + self._OPAQUE)} chars)"]

    def test_terminators_do_not_swallow_following_text(self) -> None:
        """The value class stops at whitespace, `&`, quotes and `#`.

        Wider than the `[^\\s&]+` precedent in `instances/token_mint._TOKEN_RE`
        on purpose: a quoted URL or a fragment must keep its closing quote and
        its fragment text.
        """
        cases = [
            (f"?token={self._OPAQUE} trailing prose", " trailing prose"),
            (f"?token={self._OPAQUE}#fragment", "#fragment"),
            (f'link "?token={self._OPAQUE}" quoted', '" quoted'),
            (f"link '?token={self._OPAQUE}' quoted", "' quoted"),
            (f"?token={self._OPAQUE}&next=1", "&next=1"),
            # RFC 3986-excluded bytes also terminate: a value glued to prose
            # or markup by one of them keeps everything past the stop.
            (f"?token={self._OPAQUE}<br>", "<br>"),
            (f"?token={self._OPAQUE}}}末尾", "}末尾"),
            (f"?token={self._OPAQUE}`code`", "`code`"),
        ]
        for text, kept in cases:
            result, _ = redact_credentials(text)
            assert self._OPAQUE not in result, text
            assert kept in result, text

    def test_bare_token_assignment_outside_a_query_not_matched(self) -> None:
        """The anchor is `[?&]token=`: a prose or config `token=` is not a URL
        parameter, and matching it would false-positive on ordinary text."""
        text = f"config line token={self._OPAQUE} stays"
        result, warnings = redact_credentials(text)
        assert result == text
        assert warnings == []

    def test_near_miss_parameter_names_not_matched(self) -> None:
        """Anchor-widening control: names that merely CONTAIN `token` stay.

        Each of these reds if the anchor loosens (`token[^=]*=`, a missing `=`
        or a dropped `[?&]`), which is the widening a shape-based pass invites
        and this name-keyed pass must not."""
        for text in (
            "https://h.example/?tokens=abc123 listing",
            "https://h.example/?token_id=abc123 lookup",
            "https://h.example/?mytoken=abc123 legacy",
            "https://h.example/?tokenizer=bpe model",
        ):
            result, warnings = redact_credentials(text)
            assert result == text, text
            assert warnings == [], text

    def test_parameter_name_folds_ascii_case_value_does_not(self) -> None:
        """ASCII-cased `token` names carry the same bearer value."""
        for name in ("Token", "TOKEN", "toKen"):
            text = f"https://h.example/?{name}={self._OPAQUE}"
            result, _ = redact_credentials(text)
            assert self._OPAQUE not in result, name
            assert f"{name}=[REDACTED: credential]" in result, name

    def test_named_percent_entity_is_case_sensitive(self) -> None:
        """Only the exact WHATWG named reference decodes to a percent sign."""
        from kiro_crew.security.redaction import _TOKEN_PARAM_PARTIAL_RE

        for name in ("&PERCNT;74oken", "&PerCnt;74oken"):
            text = f"?{name}={self._OPAQUE}"
            assert redact_credentials(text) == (text, []), name
            assert _TOKEN_PARAM_PARTIAL_RE.search(f"?{name}=") is None, name

        lowercase = f"?&percnt;74oken={self._OPAQUE}"
        assert redact_credentials(lowercase)[0] == ("?&percnt;74oken=[REDACTED: credential]")
        assert _TOKEN_PARAM_PARTIAL_RE.search("?&percnt;74oken=") is not None

    def test_numeric_percent_reference_keeps_ascii_hex_case_fold(self) -> None:
        """HTML numeric references accept either x case; named refs do not."""
        for name in ("&#x25;74oken", "&#X25;74oken", "&#X025;74oken"):
            text = f"?{name}={self._OPAQUE}"
            result, warnings = redact_credentials(text)
            assert result == f"?{name}=[REDACTED: credential]", name
            assert warnings == ["Redacted token parameter value (16 chars)"], name

    def test_parameter_name_rejects_unicode_casefold_homoglyphs(self) -> None:
        """Unicode case-fold lookalikes are not parser-equivalent to `token`."""
        for name in ("to\u212aen", "TO\u212aEN"):
            text = f"?{name}=somevalue"
            result, warnings = redact_credentials(text)
            assert result == text, name
            assert warnings == [], name

    def test_stream_partial_rejects_unicode_casefold_homoglyphs(self) -> None:
        """A trailing Kelvin-spelled name is not a streaming token anchor."""
        from kiro_crew.security.redaction import _TOKEN_PARAM_PARTIAL_RE

        for name in ("to\u212aen", "TO\u212aEN"):
            assert _TOKEN_PARAM_PARTIAL_RE.search(f"?{name}=") is None, name

    def test_percent_encoded_parameter_name_is_redacted(self) -> None:
        """A parser decodes `to%6ben` to `token`; the scrubber must agree."""
        text = f"https://h.example/?to%6ben={self._OPAQUE}"
        result, warnings = redact_credentials(text)
        assert result == "https://h.example/?to%6ben=[REDACTED: credential]"
        assert warnings == ["Redacted token parameter value (16 chars)"]

    def test_fully_and_mixed_encoded_parameter_names_are_redacted(self) -> None:
        for name in ("%74%6F%6B%65%6E", "to%6Ben"):
            text = f"https://h.example/?{name}={self._OPAQUE}"
            result, _ = redact_credentials(text)
            assert self._OPAQUE not in result, name
            assert result == f"https://h.example/?{name}=[REDACTED: credential]"

    def test_percent_encoded_near_miss_names_not_matched(self) -> None:
        """Wrong and invalid escapes do not decode to the `token` name."""
        for name in ("to%6Aen", "to%6gen"):
            text = f"https://h.example/?{name}=x"
            result, warnings = redact_credentials(text)
            assert result == text, name
            assert warnings == [], name

    def test_percent_encoded_name_split_mid_escape_not_leaked(self) -> None:
        """A chunk ending mid-escape holds the whole parameter until redaction."""
        from kiro_crew.security import StreamRedactor

        secret_head = self._OPAQUE[:8]
        secret_tail = self._OPAQUE[8:]
        redactor = StreamRedactor()
        emitted = [
            redactor.feed("?to%6"),
            redactor.feed("ben=" + secret_head),
            redactor.feed(secret_tail),
            redactor.flush(),
        ]
        assert all(secret_head not in piece and secret_tail not in piece for piece in emitted)
        assert "".join(emitted) == "?to%6ben=[REDACTED: credential]"

    def test_stream_partial_matches_every_encoded_name_prefix(self) -> None:
        """Every valid separator/name prefix pair stays buffered."""
        from itertools import product

        from kiro_crew.security import _CRED_CLASS
        from kiro_crew.security.redaction import _TOKEN_PARAM_PARTIAL_RE

        letter_spellings = (
            ("t", "%74", "%54", "&#116;", "&#84;", "&#x74;", "&#x54;", "&#37;74", "&percnt;74"),
            ("o", "%6F", "%4F", "&#111;", "&#79;", "&#x6f;", "&#x4f;", "&#37;6f", "&percnt;6f"),
            ("k", "%6B", "%4B", "&#107;", "&#75;", "&#x6b;", "&#x4b;", "&#37;6b", "&percnt;6b"),
            ("e", "%65", "%45", "&#101;", "&#69;", "&#x65;", "&#x45;", "&#37;65", "&percnt;65"),
            ("n", "%6E", "%4E", "&#110;", "&#78;", "&#x6e;", "&#x4e;", "&#37;6e", "&percnt;6e"),
        )
        separator_spellings = (
            "?",
            "&",
            "&amp;",
            "&AMP;",
            "&#38;",
            "&#38",
            "&#0000000038;",
            "&#x26;",
            "&#X26",
            "&#x0000000026;",
            "&quest;",
            "&#63;",
            "&#63",
            "&#0000000063;",
            "&#x3F;",
            "&#X3f",
            "&#x000000003F;",
        )
        for parts in product(*letter_spellings):
            name = "".join(parts)
            separators = separator_spellings
            if name[0] in "%&":
                separators += ("&amp", "&AMP")
            for separator in separators:
                for end in range(1, len(name) + 1):
                    prefix = name[:end]
                    assert prefix[-1] in _CRED_CLASS or _TOKEN_PARAM_PARTIAL_RE.search(
                        f"{separator}{prefix}"
                    ), f"{separator}{prefix}"

    def test_stream_holds_complete_entity_name_parts_across_chunks(self) -> None:
        """A completed entity must not release an in-progress token name."""
        from kiro_crew.security import StreamRedactor

        for first_chunk, second_chunk in (
            ("?t&#111;", "ken=" + self._OPAQUE),
            ("?&percnt;", "74oken=" + self._OPAQUE),
            ("?&#37;&#55;", "&#52;oken=" + self._OPAQUE),
        ):
            redactor = StreamRedactor()
            emitted = [redactor.feed(first_chunk)]
            assert emitted[0] == "", first_chunk
            emitted.extend((redactor.feed(second_chunk), redactor.flush()))
            joined = "".join(emitted)
            assert self._OPAQUE not in joined, first_chunk
            assert "[REDACTED: credential]" in joined, first_chunk

    def test_fully_composed_anchor_fits_stream_holdback_bound(self) -> None:
        """The longest separator plus five composed letters remains bounded."""
        from kiro_crew.security import _STREAM_HOLDBACK_MAX

        def html_hex_byte(byte: str) -> str:
            return f"&#x{'0' * 8}{ord(byte):X};"

        separator = "&#x000000003F;"
        name = "".join(
            "".join(html_hex_byte(byte) for byte in f"%{ord(letter):x}") for letter in "token"
        )
        anchor = separator + name
        assert len(anchor) <= 224
        assert len(anchor) < _STREAM_HOLDBACK_MAX

    def test_html_entity_separators_and_equals_are_redacted(self) -> None:
        """Every bounded HTML5 spelling decoded before query parsing is structure."""
        cases = (
            ("?", "token", "="),
            ("?", "t&#111;ken", "="),
            ("&", "token", "="),
            ("&amp;", "token", "="),
            ("&amp;", "t&#111;ken", "&equals;"),
            ("&AMP;", "token", "="),
            ("&amp", "%74oken", "="),
            ("&AMP", "%74oken", "="),
            ("&amp", "&#116;oken", "="),
            ("&AMP", "&#x74;oken", "="),
            ("&#38;", "token", "="),
            ("&#38", "token", "="),
            ("&#0000000038;", "token", "="),
            ("&#x26;", "token", "="),
            ("&#X26", "token", "="),
            ("&#x0000000026;", "token", "="),
            ("&quest;", "token", "="),
            ("&#63;", "token", "="),
            ("&#63", "token", "="),
            ("&#0000000063;", "token", "="),
            ("&#x3F;", "token", "="),
            ("&#X3f", "token", "="),
            ("&#x000000003F;", "token", "="),
            ("?", "&#x74;oken", "="),
            ("?", "&#84;oken", "="),
            ("?", "&#37;74oken", "="),
            ("?", "&percnt;74oken", "="),
            ("?", "%&#55;&#52;oken", "="),
            ("?", "&#x25;&#x37;&#x34;oken", "="),
            ("?", "t%6&#70;ken", "="),
            ("?", "t%6&#102;ken", "="),
            ("?", "t&#111ken", "="),
            ("?", "token", "&equals;"),
            ("?", "token", "&#61;"),
            ("?", "token", "&#61"),
            ("?", "token", "&#0000000061;"),
            ("?", "token", "&#x3D;"),
            ("?", "token", "&#X3d"),
            ("?", "token", "&#x000000003D;"),
        )
        for separator, name, equals in cases:
            anchor = f"{separator}{name}{equals}"
            result, warnings = redact_credentials(f"{anchor}{self._OPAQUE}")
            assert result == f"{anchor}[REDACTED: credential]", anchor
            assert warnings == ["Redacted token parameter value (16 chars)"], anchor

    def test_non_decoding_separator_and_equals_spellings_are_unchanged(self) -> None:
        """Near entities, double encodings, and later-stage escapes stay data."""
        texts = (
            f"&amptoken={self._OPAQUE}",
            f"&Amp;token={self._OPAQUE}",
            f"&questtoken={self._OPAQUE}",
            f"?token&equals{self._OPAQUE}",
            f"&amp;amp;token={self._OPAQUE}",
            f"%26token={self._OPAQUE}",
            f"?token%3D{self._OPAQUE}",
            f"&#382token={self._OPAQUE}",
            f"?token&#61123abc{self._OPAQUE}",
            f"&#{'0' * 9}38;token={self._OPAQUE}",
            f"?&percnt74oken={self._OPAQUE}",
            f"?&#{'0' * 9}116;oken={self._OPAQUE}",
            f"&ampToken={self._OPAQUE}",
        )
        for text in texts:
            result, warnings = redact_credentials(text)
            assert result == text, text
            assert warnings == [], text

    def test_source_and_doc_templates_not_matched(self) -> None:
        """A token-URL TEMPLATE in source or docs must survive.

        The value class excludes the RFC 3986-forbidden bytes, so a value
        beginning with one -- an f-string placeholder, a markdown backtick, an
        angle-bracket placeholder -- is no match at all. This is the chip-diff
        surface: `chat_runner.py` redacts file snapshots IN PLACE, so a false
        positive here rewrites a snapshot of `dashboard/urls.py` with no
        recovery path."""
        for text in (
            'url = f"{base}?token={token}"',
            "open `http://host:7777?token=` in a browser",
            "http://localhost:7777?token=<your-token-here>",
            "curl {base}?token={quote(tok)} --silent",
        ):
            result, warnings = redact_credentials(text)
            assert result == text, text
            assert warnings == [], text

    def test_value_already_caught_by_pass_1_is_byte_identical(self) -> None:
        """A pass-1-shaped value keeps pass 1's tag and single warning.

        Pass 4 ranks last and claims only uncovered gaps, so outputs existing
        callers assert on do not change for values the scrubber already caught.
        """
        result, warnings = redact_credentials("?token=AKIAIOSFODNN7EXAMPLE")
        assert result == "?token=[REDACTED: credential]"
        assert warnings == ["Redacted credential pattern (20 chars)"]

    def test_value_already_caught_by_pass_3_is_single_tagged(self) -> None:
        """A bare 40-char secret AS the token value is claimed once, by pass 3.

        This pins the `taken = sorted(taken + pass3)` fold ahead of pass 4:
        without it, pass 4 re-claims the span pass 3 took, `_splice` receives
        overlapping spans, the tag doubles, and the dashboard's redaction
        notice counts two credentials where one was removed.
        """
        secret = "wJalrXUtnFEMI/K7MDENG/" "bPxRfiCYEXAMPLEKEY"
        result, warnings = redact_credentials(f"?token={secret}")
        assert result == "?token=[REDACTED: credential]"
        assert warnings == [f"Redacted bare secret key ({len(secret)} chars)"]

    def test_redacted_output_is_a_fixed_point(self) -> None:
        """Canonical credential tags are fixed points; an exfil tag collapses once."""
        for text in (
            f"?token={self._OPAQUE}",
            f"https://h.example/?token=AKIAIOSFODNN7EXAMPLE&x=1 and ?token={self._OPAQUE}",
        ):
            once, _ = redact_credentials(text)
            twice, warnings = redact_credentials(once)
            assert twice == once, text
            assert warnings == [], text

        exfil_tagged = "?token=[REDACTED: suspicious URL to collect.example]"
        once, _ = redact_credentials(exfil_tagged)
        twice, warnings = redact_credentials(once)
        assert once != exfil_tagged
        assert twice == once
        assert warnings == []

    def test_attacker_authored_redaction_prefix_does_not_bypass(self) -> None:
        """A redaction-shaped prefix is untrusted unless it is a fixed literal."""
        secret = "sk_live_51H8xY2abcdefghijklmnop"
        result, _ = redact_credentials(f"?token=[REDACTED{secret}")
        assert result.startswith("?token=[REDACTED: credential]")
        assert "[REDACTED: credential]" in result
        assert secret not in result

        from kiro_crew.security import StreamRedactor

        redactor = StreamRedactor()
        emitted = [
            redactor.feed("?token=[REDACTED"),
            redactor.feed(secret),
            redactor.flush(),
        ]
        joined = "".join(emitted)
        assert all(secret not in piece for piece in emitted)
        assert joined.startswith("?token=[REDACTED: credential]")
        assert secret not in joined

    def test_fake_exfil_tags_do_not_bypass(self) -> None:
        """Pass 4 claims only group(1), so the post-space residual matches the
        tag-free witness ``?token=a Zk8q.co`` while the value head is redacted.
        """
        contiguous = "?token=[REDACTED:suspicious-URL-to-Zk8q.co]"
        result, _ = redact_credentials(contiguous)
        assert result == "?token=[REDACTED: credential]"
        assert "Zk8q.co" not in result

        spaced = "?token=[REDACTED: suspicious URL to Zk8q.co]"
        result, _ = redact_credentials(spaced)
        assert result == "?token=[REDACTED: credential] suspicious URL to Zk8q.co]"

    def test_registered_credential_tags_are_fixed_points(self) -> None:
        """Every module-owned credential-tag literal is trusted by construction."""
        from kiro_crew.security import CREDENTIAL_REDACTION_TAGS

        for tag in CREDENTIAL_REDACTION_TAGS:
            text = f"?token={tag}"
            result, warnings = redact_credentials(text)
            assert result == text
            assert warnings == []

    def test_blocking_surface_unchanged(self) -> None:
        """Redaction-only: `_contains_fixed_credential` gates request-BLOCKING
        decisions in `exfil.py` and must not learn the parameter name -- a
        `?token=` URL is maskable output, never itself grounds to block."""
        from kiro_crew.security.redaction import _contains_fixed_credential

        assert not _contains_fixed_credential(f"https://h.example/?token={self._OPAQUE}")

    def test_exfil_first_composition_still_replaces_the_whole_url(self) -> None:
        """A long opaque token must not defeat the whole-URL exfil redaction.

        `redact_exfiltration_urls` classifies partly by query LENGTH and
        replaces the ENTIRE url. Pass 4 shortening `?token=<210 chars>` to its
        tag ahead of that scan would drop the query below the threshold, so
        the attacker host and every OTHER parameter -- the actual payload,
        which no name-keyed pass matches -- would render verbatim. The
        canonical composition (`redact` / `redact_with_findings`) runs the
        exfil pass FIRST, and this pins that pass 4 does not break it.
        """
        from kiro_crew.security import redact

        url = (
            "fetching https://collect.attacker.example/?token="
            + "aB3" * 70
            + "&host=corp-laptop&path=/home/alice/.aws/credentials"
        )
        out = redact(url)
        # The whole URL is replaced by the exfil tag, which NAMES the domain by
        # design ("suspicious URL to <domain>") -- what must be gone is the
        # fetchable URL and the payload parameters, not the domain word.
        assert out == "fetching [REDACTED: suspicious URL to collect.attacker.example]"
        assert "corp-laptop" not in out
        assert "/home/alice/.aws/credentials" not in out
        assert "?token=" not in out


class TestTokenParamExemptUrlPrefixes:
    """Companion URL prefixes whose ``?token=`` value pass 4 leaves alone.

    NEUTRAL PLACEHOLDER PREFIX ONLY: a companion's real approval host never
    appears in the public repo.
    """

    _PREFIX = "https://approve.example.com/auth"
    _TOKEN = "eyJ3b3JrZmxvd0lkIjoiMDAwMDAwMDAtMDAwMC00MDAwLTgwMDAtMDAwMDAwMDAwMDAwIn0%3D"

    class _StubCredentialPolicy:
        def __init__(self, prefixes: object):
            self._prefixes = prefixes

        def redact(self, text: str) -> str:
            from kiro_crew.security import redact

            return redact(text)

        def exempt_exact_hosts(self) -> "frozenset[str]":
            # The display battery also runs the exfil pass; exempt its heuristics
            # so the cache test isolates pass 4.
            return frozenset({"approve.example.com"})

        def token_param_exempt_url_prefixes(self) -> object:
            if isinstance(self._prefixes, Exception):
                raise self._prefixes
            return self._prefixes

    def _install(self, prefixes: object) -> None:
        import dataclasses

        from kiro_crew.config import KiroCrewConfig
        from kiro_crew.platform.bootstrap import build_default_context
        from kiro_crew.platform.context import set_context

        base = build_default_context(KiroCrewConfig())
        set_context(dataclasses.replace(base, credentials=self._StubCredentialPolicy(prefixes)))

    @property
    def _url(self) -> str:
        return f"{self._PREFIX}?token={self._TOKEN}"

    def test_default_redacts(self) -> None:
        out, warnings = redact_credentials(self._url)
        assert self._TOKEN not in out
        assert warnings == [f"Redacted token parameter value ({len(self._TOKEN)} chars)"]

    @pytest.mark.parametrize(
        "text",
        [
            "{u}",
            "Approve {u}",
            "[link]({u})",
            "<{u}>",
            '"{u}"',
            "'{u}'",
            "`{u}`",
            "*{u}*",
        ],
    )
    def test_exempt_prefix_keeps_value(self, text: str) -> None:
        self._install(frozenset({self._PREFIX}))
        rendered = text.format(u=self._url)
        assert redact_credentials(rendered) == (rendered, [])

    @pytest.mark.parametrize(
        "text",
        [
            "[Approve](https://evil.example/?next=({u}))",
            "[Approve](//evil.example/?next=[x]({u}))",
            "[Approve](/redirect?next=[x]({u}))",
            "https://evil.example/?next=({u})",
            "https://evil.example/?next=[{u}]",
            "https://evil.example/?next=<{u}>",
            'https://evil.example/?next="{u}"',
            "https://evil.example/?next='{u}'",
            "https://evil.example/?next=`{u}`",
            "https://evil.example/?next=*{u}*",
        ],
    )
    def test_prefix_nested_in_another_url_is_not_exempt(self, text: str) -> None:
        self._install(frozenset({self._PREFIX}))
        assert self._TOKEN not in redact_credentials(text.format(u=self._url))[0]

    @pytest.mark.parametrize(
        "text",
        [
            '<a href="https://evil.example/?next=\t{u}">Approve</a>',
            '<a href="https://evil.example/?next=\n{u}">Approve</a>',
            '<a href="https://evil.example/?next=\r{u}">Approve</a>',
            '<a href="https://evil.example/?next= {u}">Approve</a>',
            "<https://evil.example/?next= {u}>",
            'href="//evil.example/?next=\t{u}"',
            'href="https:\\evil.example/?next=\t{u}"',
            'href="https:evil.example/?next=\t{u}"',
        ],
    )
    def test_browser_destination_embedding_is_not_exempt(self, text: str) -> None:
        self._install(frozenset({self._PREFIX}))
        assert self._TOKEN not in redact_credentials(text.format(u=self._url))[0]

    @pytest.mark.parametrize(
        "text",
        [
            "[Approve](<&sol;&sol;evil.example/?next= {u}>)",
            "[Approve](<&#104;ttps&#58;&#47;&#47;evil.example/?next= {u}>)",
            '<a href="&#x2F;&#x2F;evil.example/?next=\t{u}">Approve</a>',
            "&amp; {u}",
            "<x> {u}",
        ],
    )
    def test_encoded_or_tagged_destination_is_not_exempt(self, text: str) -> None:
        """A renderer decodes character references inside ``<...>`` and attributes, so
        the raw-text guard treats any ``&`` or ``<`` before the prefix as a
        destination signal instead of decoding it (double-encoding and renderer
        differences make decoding a moving target). Doubt means MORE redaction.
        """
        self._install(frozenset({self._PREFIX}))
        assert self._TOKEN not in redact_credentials(text.format(u=self._url))[0]

    def test_multiple_standalone_exempt_links_keep_both_values(self) -> None:
        self._install(frozenset({self._PREFIX}))
        text = f"- [First]({self._url})\n- [Second]({self._url})"
        assert redact_credentials(text) == (text, [])

    def test_multiple_autolinked_exempt_links_keep_both_values(self) -> None:
        """An exempt URL's own ``<`` opener is blanked with it, so it is not a tag signal."""
        self._install(frozenset({self._PREFIX}))
        text = f"- <{self._url}>\n- <{self._url}>"
        assert redact_credentials(text) == (text, [])

    def test_prose_label_before_exempt_link_keeps_value(self) -> None:
        self._install(frozenset({self._PREFIX}))
        text = f"Approve: {self._url}"
        assert redact_credentials(text) == (text, [])

    @pytest.mark.parametrize(
        "url",
        [
            "https://approve.example.com.evil.example/auth?token={t}",
            "https://x.approve.example.com/auth?token={t}",
            "https://user@approve.example.com/auth?token={t}",
            "http://approve.example.com/auth?token={t}",
            "https://approve.example.com/other?token={t}",
            "https://approve.example.com/auth/x?token={t}",
            "https://approve.example.com/auth?a=1&token={t}",
            "https://approve.example.com/auth?TOKEN={t}",
            "https://approve.example.com/auth&#63;token={t}",
            "xhttps://approve.example.com/auth?token={t}",
            "https://redirect.example/?next=https://approve.example.com/auth?token={t}",
            "https://redirect.example/https://approve.example.com/auth?token={t}",
            "https://redirect.example/#https://approve.example.com/auth?token={t}",
            "x:https://approve.example.com/auth?token={t}",
            "x@https://approve.example.com/auth?token={t}",
        ],
    )
    def test_other_shapes_still_redacted(self, url: str) -> None:
        self._install(frozenset({self._PREFIX}))
        assert self._TOKEN not in redact_credentials(url.format(t=self._TOKEN))[0]

    def test_earlier_pass_claim_keeps_whole_value_redacted(self) -> None:
        self._install(frozenset({self._PREFIX}))
        out = redact_credentials(f"{self._PREFIX}?token={self._TOKEN}AKIAIOSFODNN7EXAMPLE")[0]
        assert self._TOKEN not in out
        assert "AKIAIOSFODNN7EXAMPLE" not in out

    @pytest.mark.parametrize(
        "text",
        [
            "[A]({u}),[B](https://svc.example/cb?token=SECRET)",
            "[A]({u})[B](https://svc.example/cb?token=SECRET)",
            "{u}?token=SECRET",
            "{u}/cb?token=SECRET",
            "{u}:SECRET",
            "{u}(SECRET)",
            "{u}[SECRET]",
        ],
    )
    def test_value_run_past_the_token_is_not_exempt(self, text: str) -> None:
        """`_TOKEN_PARAM_VALUE_CLASS` admits `)`, `,`, `(`, `[`, `:` and `?`, so one
        pass-4 match can swallow a second URL after the exempt token. The exemption
        covers one unreserved/base64/percent-encoded run plus trailing closers only;
        anything else redacts the WHOLE value, which is also its re-redaction fixed point.
        """
        self._install(frozenset({self._PREFIX}))
        out, warnings = redact_credentials(text.format(u=self._url))
        assert "SECRET" not in out
        assert self._TOKEN not in out
        assert len(warnings) == 1 and warnings[0].startswith("Redacted token parameter value (")
        assert redact_credentials(out) == (out, [])

    @pytest.mark.parametrize("trail", [")", ").", "),", "]", "]:", "?", "!", ";"])
    def test_trailing_closers_after_the_token_stay_exempt(self, trail: str) -> None:
        self._install(frozenset({self._PREFIX}))
        text = f"Open {self._url}{trail} then wait"
        assert redact_credentials(text) == (text, [])

    @pytest.mark.parametrize(
        "prefixes",
        [
            frozenset({"https://approve.example.com"}),
            frozenset({"approve.example.com/auth"}),
            frozenset({"http://approve.example.com/auth"}),
            frozenset({"https://approve.example.com/auth?"}),
            frozenset({b"https://approve.example.com/auth"}),
            None,
            RuntimeError("adapter bug"),
        ],
    )
    def test_malformed_or_failing_seam_degrades_to_redaction(self, prefixes: object) -> None:
        self._install(prefixes)
        assert self._TOKEN not in redact_credentials(self._url)[0]

    def test_pre_method_adapter_degrades_to_redaction(self) -> None:
        import dataclasses

        from kiro_crew.config import KiroCrewConfig
        from kiro_crew.platform.bootstrap import build_default_context
        from kiro_crew.platform.context import set_context

        class _Old:
            def redact(self, text: str) -> str:
                return text

            def exempt_exact_hosts(self) -> "frozenset[str]":
                return frozenset()

        base = build_default_context(KiroCrewConfig())
        set_context(dataclasses.replace(base, credentials=_Old()))
        assert self._TOKEN not in redact_credentials(self._url)[0]

    def test_stream_windows_never_apply_the_exemption(self) -> None:
        from kiro_crew.security import REDACTED_CREDENTIAL_TAG, StreamRedactor

        self._install(frozenset({self._PREFIX}))
        split_messages = (
            ("[Approve](https://evil.example/?next=(", f"{self._url})) "),
            ('<a href="https://evil.example/?next= ', f'{self._url}">Approve</a>'),
        )
        for chunks in split_messages:
            redactor = StreamRedactor()
            streamed = "".join(redactor.feed(chunk) for chunk in chunks) + redactor.flush()
            assert self._TOKEN not in streamed
            assert REDACTED_CREDENTIAL_TAG in streamed

    def test_plain_approval_link_is_redacted_only_while_streaming(self) -> None:
        from kiro_crew.security import REDACTED_CREDENTIAL_TAG, StreamRedactor

        self._install(frozenset({self._PREFIX}))
        redactor = StreamRedactor()
        streamed = redactor.feed(f"{self._url} ") + redactor.flush()
        assert self._TOKEN not in streamed
        assert REDACTED_CREDENTIAL_TAG in streamed
        assert redact_credentials(self._url) == (self._url, [])

    def test_stream_suspension_resets_after_custom_redactor_exception(self) -> None:
        from kiro_crew.security import StreamRedactor

        self._install(frozenset({self._PREFIX}))

        def raising_redactor(text: str) -> str:
            assert self._TOKEN not in redact_credentials(self._url)[0]
            raise RuntimeError("redactor failed")

        redactor = StreamRedactor(raising_redactor)
        with pytest.raises(RuntimeError, match="redactor failed"):
            redactor.feed("safe text ")
        assert redact_credentials(self._url) == (self._url, [])

    def test_display_cache_key_covers_the_prefix_set(self) -> None:
        from kiro_crew.dashboard import chat_utils

        chat_utils._clear_display_redaction_cache()
        assert self._TOKEN not in chat_utils._redact_for_display(self._url)
        self._install(frozenset({self._PREFIX}))
        assert chat_utils._redact_for_display(self._url) == self._url
        chat_utils._clear_display_redaction_cache()

    def test_repeated_exempt_links_stay_linear(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Every scanner operation examines only a constant multiple of the input."""
        from kiro_crew.security import redaction as redaction_module

        work = {"boundary": 0, "destination": 0, "scheme": 0}
        calls = {"boundary": 0, "destination": 0}
        real_boundary = redaction_module._TokenParamExemptScan.boundary
        real_destination = redaction_module._token_param_destination_signal
        real_scheme = redaction_module._token_param_has_scheme_before

        def counting_boundary(scan: object, sep: int, start: int) -> bool:
            ws_cursor = scan.ws_cursor
            result = real_boundary(scan, sep, start)
            calls["boundary"] += 1
            work["boundary"] += 4 * max(0, sep - ws_cursor)
            if scan.last_ws + 1 >= scan.left_floor:
                work["boundary"] += max(0, start - scan.last_ws - 1)
            return result

        def counting_destination(text: str, start: int, end: int) -> bool:
            calls["destination"] += 1
            work["destination"] += end - start
            return real_destination(text, start, end)

        def counting_scheme(text: str, start: int, colon: int) -> bool:
            i = colon - 1
            while i >= start and text[i] in redaction_module._TOKEN_PARAM_SCHEME_CHARS:
                work["scheme"] += 1
                i -= 1
            return real_scheme(text, start, colon)

        monkeypatch.setattr(redaction_module._TokenParamExemptScan, "boundary", counting_boundary)
        monkeypatch.setattr(
            redaction_module, "_token_param_destination_signal", counting_destination
        )
        monkeypatch.setattr(redaction_module, "_token_param_has_scheme_before", counting_scheme)

        self._install(frozenset({self._PREFIX}))
        link = f"{self._PREFIX}?token=x"
        cases = (
            (f"{link} " * 20_000, True),
            ("& " + f"{link} " * 20_000, False),
            ("a" * 200_000 + " " + link, True),
            ("a1" * 100_000 + " " + link, True),
            ("a: " * 70_000 + link, True),
            ("a:" * 100_000 + link, False),
        )
        assert redaction_module._TOKEN_PARAM_DESTINATION_SIGNAL_RE.pattern == r"//|\\|&|<|:(?=\S)"
        for text, kept in cases:
            before = sum(work.values())
            out, _warnings = redact_credentials(text)
            assert (out == text) is kept
            assert sum(work.values()) - before <= 8 * len(text)
        assert calls["boundary"] > 0
        assert calls["destination"] > 0

    @staticmethod
    def _reference_token_param_exempt(
        text: str,
        m: "re.Match[str]",
        prefixes: tuple[str, ...],
        earlier_exempt_urls: list[tuple[int, int]],
    ) -> tuple[int, int] | None:
        """The seam's guards as first written: each candidate re-reads its whole prefix."""
        from kiro_crew.security.redaction import (
            _TOKEN_PARAM_DESTINATION_SIGNAL_RE,
            _TOKEN_PARAM_EXEMPT_OPENERS,
            _TOKEN_PARAM_EXEMPT_TRAIL,
            _TOKEN_PARAM_EXEMPT_VALUE_RE,
        )

        def boundary(start: int) -> bool:
            left = text[max(text.rfind(c, 0, start) for c in " \t\r\n") + 1 : start]
            if "://" in left:
                return False
            markdown_opener = re.fullmatch(r"\[[^][]*\]\(", left) is not None
            return not left or left in _TOKEN_PARAM_EXEMPT_OPENERS or markdown_opener

        def preceding_context(start: int) -> bool:
            pieces: list[str] = []
            cursor = 0
            for exempt_start, exempt_end in (*earlier_exempt_urls, (start, start)):
                if exempt_start > 0 and text[exempt_start - 1] == "<":
                    exempt_start -= 1
                pieces.extend((text[cursor:exempt_start], " " * (exempt_end - exempt_start)))
                cursor = exempt_end
            return _TOKEN_PARAM_DESTINATION_SIGNAL_RE.search("".join(pieces)) is None

        sep = m.start()
        if not text.startswith("?token=", sep):
            return None
        run = _TOKEN_PARAM_EXEMPT_VALUE_RE.match(text, m.start(1))
        if run is None or not set(text[run.end() : m.end(1)]) <= _TOKEN_PARAM_EXEMPT_TRAIL:
            return None
        for prefix in prefixes:
            start = sep - len(prefix)
            if (
                start >= 0
                and text.startswith(prefix, start)
                and boundary(start)
                and preceding_context(start)
            ):
                return start, run.end()
        return None

    def test_incremental_guards_match_the_whole_prefix_reference(self) -> None:
        """The cursor-based guards answer exactly as the whole-prefix statements do.

        Every pass-4 match of each text is put to both, in order, and also every
        other match, since the plan skips matches an earlier pass already claimed.
        """
        from kiro_crew.security.redaction import (
            _TOKEN_PARAM_RE,
            _token_param_exempt,
            _TokenParamExemptScan,
        )

        long_prefix = f"https://go.example/{self._PREFIX}"
        prefixes = tuple(sorted((self._PREFIX, long_prefix)))
        link = f"{self._PREFIX}?token=x"
        pieces = [
            link,
            f"<{link}>",
            f"[Approve]({link})",
            f"[Approve]({link}),",
            f"({link})",
            f"'{link}'",
            f"{long_prefix}?token=x",
            f"<{long_prefix}?token=x>",
            f"{link}?token=SECRET",
            "https://svc.example/cb?token=SECRET",
            f"https://evil.example/?next=({link})",
            f"[Approve](/redirect?next=[x]({link}))",
            f'<a href="https://evil.example/?next= {link}">Approve</a>',
            "&amp;",
            "&sol;&sol;evil.example",
            "<x>",
            "x:",
            "x:y",
            "foo:",
            "1abc:d",
            "a1" * 5 + ":x",
            ": y",
            "+.-a:b",
            "\\",
            "//",
            "Approve:",
            "plain words",
            "",
        ]
        separators = [" ", "\n", "\t", "", "<", ">", ")", "](", "/", ":"]
        rng = random.Random(20261008)
        texts = [
            sep.join([a, b, c]) for a in pieces for b in pieces for c in pieces for sep in " \n"
        ]
        texts.extend(
            rng.choice(separators).join(rng.choice(pieces) for _ in range(rng.randint(1, 9)))
            for _ in range(3000)
        )
        texts.extend(sep.join([link, link, link]) for sep in separators)
        for text in texts:
            for stride in (1, 2):
                scan = _TokenParamExemptScan(text)
                earlier: list[tuple[int, int]] = []
                for i, m in enumerate(_TOKEN_PARAM_RE.finditer(text)):
                    if i % stride:
                        continue
                    expected = self._reference_token_param_exempt(text, m, prefixes, earlier)
                    assert _token_param_exempt(text, m, prefixes, scan) == expected, (text, m)
                    if expected is not None:
                        earlier.append(expected)
                        scan.accept(expected)


class TestRedactCredentialsBase64:
    """Tests for base64-encoded credential detection."""

    def test_detects_base64_encoded_access_key(self) -> None:
        secret = "AccessKeyId=AKIAIOSFODNN7EXAMPLE SecretAccessKey=wJalrXUtnFEMI"
        encoded = base64.b64encode(secret.encode()).decode()
        text = f"Output: {encoded}"
        result, warnings = redact_credentials(text)
        assert encoded not in result
        assert "[REDACTED:" in result

    def test_detects_base64_encoded_secret_key(self) -> None:
        secret = "SecretAccessKey=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        encoded = base64.b64encode(secret.encode()).decode()
        text = f"Result: {encoded}"
        result, warnings = redact_credentials(text)
        assert encoded not in result

    def test_detects_base64_private_key(self) -> None:
        secret = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA"
        encoded = base64.b64encode(secret.encode()).decode()
        text = f"Data: {encoded}"
        result, warnings = redact_credentials(text)
        assert encoded not in result

    def test_ignores_benign_base64(self) -> None:
        # Normal base64 that doesn't decode to credentials
        text = "aW1wb3J0IHRoaXM=  # import this"
        result, warnings = redact_credentials(text)
        assert result == text

    def test_ignores_short_base64(self) -> None:
        text = "SGVsbG8="  # "Hello" — too short to trigger (< 40 chars)
        result, warnings = redact_credentials(text)
        assert result == text


class TestBareSecretKeyRedaction:
    """Label-independent 40-char AWS secret-key redaction (security-review bf7b1baf).

    A bare 40-char base64 secret (the value paired with an AKIA/ASIA access key
    ID) carries no distinctive prefix and no ``key=`` label, so the labelled
    patterns miss it when it appears standalone. These tests prove the
    entropy + structural heuristic catches real secret shapes WITHOUT
    over-redacting git SHAs, hex digests, UUIDs, code identifiers, or file paths.
    """

    # ── TRUE POSITIVES: real 40-char secret-key shapes must be redacted ──

    def test_redacts_bare_aws_example_secret_key(self) -> None:
        # The canonical AWS documentation example secret access key, standalone
        # (no label, no AKIA sibling) — the exact gap the finding describes.
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result, warnings = redact_credentials(secret)
        assert secret not in result
        assert "[REDACTED: credential]" in result
        assert warnings

    def test_redacts_bare_secret_in_prose_context(self) -> None:
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        text = f"Here is the key: {secret} — keep it safe"
        result, _ = redact_credentials(text)
        assert secret not in result
        assert "keep it safe" in result  # surrounding prose preserved

    def test_redacts_bare_secret_in_json_array(self) -> None:
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        text = f'{{"keys": ["{secret}"]}}'
        result, _ = redact_credentials(text)
        assert secret not in result

    def test_redacts_duplicate_bare_secret_occurrences(self) -> None:
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        text = f"{secret} and again {secret}"
        result, _ = redact_credentials(text)
        assert secret not in result  # BOTH copies gone

    @pytest.mark.parametrize(
        "secret",
        [
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # AWS doc example (40 chars)
            "Kx3Q51tPusV/D0URlGfMmNbVc7Z8yJhLpQrStUwZ",  # random, with '/' (40 chars)
            "Kx3Q51tPusVkD0URlGfMmNbVc7Z8yJhLpQrStUwZ",  # random alnum (40 chars)
            "Zx9Kq2Wm7Vn4Bc1Xz8Lp5Rt3Yd6Fg0Hj2Ns4QwYt",  # random alnum (40 chars)
        ],
    )
    def test_redacts_various_bare_secret_shapes(self, secret: str) -> None:
        assert len(secret) == 40  # guard: AWS secret-key length
        result, _ = redact_credentials(secret)
        assert secret not in result, f"bare secret leaked: {secret!r}"

    def test_redacts_secret_glued_to_adjacent_base64_char(self) -> None:
        # A real 40-char secret glued to an adjacent base64 char with NO delimiter
        # produces a 41+ char run that the exact-40 length gate would miss, leaking
        # the key verbatim. The sliding 40-char window must still catch it. Covers:
        # X+secret, secret+A, SECRET=+secret+ABC, and secret+X+secret.
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        for label, text in [
            ("prefix char", "X" + secret),
            ("suffix char", secret + "A"),
            ("labelled + trailing", "SECRET=" + secret + "ABC"),
            ("two secrets joined by one char", secret + "X" + secret),
        ]:
            result, warnings = redact_credentials(text)
            assert secret not in result, f"glued secret leaked ({label}): {result!r}"
            assert "[REDACTED: credential]" in result, label
            assert warnings, label

    # ── TRUE NEGATIVES: high-FP-risk lookalikes must NOT be redacted ──

    def test_git_sha_not_redacted(self) -> None:
        # 40-char hex git commit SHA — must survive untouched.
        for sha in [
            "da39a3ee5e6b4b0d3255bfef95601890afd80709",
            "356a192b7913b04c54574d18c28d46e6395428ab",
            "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709",  # upper hex
            "Da39A3ee5E6b4B0d3255BfeF95601890AfD80709",  # mixed hex
        ]:
            result, warnings = redact_credentials(sha)
            assert result == sha, f"git SHA over-redacted: {sha!r}"
            assert not warnings

    def test_sha256_hex_not_redacted(self) -> None:
        digest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result, warnings = redact_credentials(digest)
        assert result == digest
        assert not warnings

    def test_md5_hex_not_redacted(self) -> None:
        digest = "d41d8cd98f00b204e9800998ecf8427e"
        result, warnings = redact_credentials(digest)
        assert result == digest
        assert not warnings

    def test_uuid_not_redacted(self) -> None:
        for u in [
            "550e8400-e29b-41d4-a716-446655440000",
            "550E8400-E29B-41D4-A716-446655440000",
        ]:
            result, _ = redact_credentials(u)
            assert result == u, f"UUID over-redacted: {u!r}"

    def test_ordinary_prose_not_redacted(self) -> None:
        text = "The quick brown fox jumps over the lazy dog once more today."
        result, warnings = redact_credentials(text)
        assert result == text
        assert not warnings

    def test_camelcase_identifier_not_redacted(self) -> None:
        # 40-char camelCase/PascalCase code identifiers with digits — the class
        # that overlaps real keys on entropy alone. The structural gates
        # (longest-lowercase-run + vowel-ratio) must keep them intact.
        for ident in [
            "AbstractSingletonProxyFactoryBean2Impl3",
            "getUserProfileByIdAndReturnJsonV2Respon",
            "configLoaderV3ParseYamlAndMergeDefaults1",
            "ThisIsA40CharacterCamelCaseIdentifier12T",
            "React2ComponentWithHooksAndStateManager1",
            "HTTPResponseHandlerV2ForJsonAndXmlData12",
        ]:
            result, warnings = redact_credentials(ident)
            assert result == ident, f"identifier over-redacted: {ident!r}"
            assert not warnings

    def test_long_camelcase_identifier_run_not_over_redacted(self) -> None:
        # The sliding 40-char window must not turn a benign >40-char camelCase
        # identifier run into a false positive: NO window within it may look like
        # a secret. Regression guard for the glued-secret fix.
        for ident in [
            "getUserProfileByIdAndReturnJsonV2ResponseHandlerFactoryImpl",
            "AbstractSingletonProxyFactoryBeanConfigurationLoaderV3Parser",
        ]:
            assert len(ident) > 40
            result, warnings = redact_credentials(ident)
            assert result == ident, f"identifier run over-redacted: {ident!r}"
            assert not warnings

    def test_slash_delimited_file_paths_not_redacted(self) -> None:
        # 40-char mixed-case file/package paths contain '/' (a base64 char) but
        # are benign. Regression guard: the heuristic must NOT treat '/' as a
        # free pass to redact — every '/' token still has to clear the structural
        # gates, and dictionary-word path segments fail them.
        for path in [
            "src/main/java/com/Example/FooBarBazClas1",  # exactly 40 chars
            "MyClass1/MyOther2/MyThird3/MyFourthClas4",  # exactly 40 chars
        ]:
            assert len(path) == 40  # guard: same length as an AWS secret key
            result, warnings = redact_credentials(path)
            assert result == path, f"file path over-redacted: {path!r}"
            assert not warnings

    def test_base32_and_digit_runs_not_redacted(self) -> None:
        for token in [
            "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXPJBSWY3DP",  # base32 (no lowercase)
            "1234567890123456789012345678901234567890",  # digits only
            "abcdefghijklmnopqrstuvwxyzabcdefghijklmn",  # lowercase only
        ]:
            result, warnings = redact_credentials(token)
            assert result == token, f"token over-redacted: {token!r}"
            assert not warnings

    def test_base64_of_readable_text_not_over_redacted_as_bare(self) -> None:
        # A base64 blob that decodes to printable text is handled by the
        # encoded-credential path, not the bare-secret heuristic; a benign one
        # must survive untouched.
        blob = base64.b64encode(b"the quick brown fox jumps over lazyy").decode()[:40]
        result, warnings = redact_credentials(blob)
        assert result == blob
        assert not warnings


class TestPathWindowsAreNotBareSecrets:
    """A deep CamelCase absolute path must survive ``redact_credentials``.

    ``/`` is in ``_B64_CHUNK_RE``'s character class, so an absolute path built
    from CamelCase segments is ONE base64-alphabet run -- it breaks only at
    ``-``, ``_``, ``.`` or whitespace. ``_contains_bare_secret`` slides a 40-char
    window across it, and a window cut from two or three components defeats the
    structural gates on their own terms: CamelCase caps the lowercase run,
    consonant-heavy acronyms crush the vowel ratio, a version digit supplies the
    third character class, and the separators lift the entropy. One passing window
    replaced the WHOLE run, so the path came back as the tag and every consumer
    that dereferences it -- a file-path chip, a screenshot note -- got an unusable
    string instead of a path.

    ``_SECRET_MAX_SLASHES`` declines such a window, and the two properties that
    keep it from being a hole are pinned below: every window is still classified,
    and a run of exactly one key length is never subject to the ceiling.
    """

    # ── benign paths must survive ──

    @pytest.mark.parametrize(
        "path",
        [
            # The reported shape: consonant-heavy acronyms plus a version digit.
            "/Volumes/workplace/TRAM/QuickProp2/src/ATVTramQuickPropCDK/lib/config/consumerVpcs.ts",
            "/Volumes/workplace/CMS/A3P3/src/LPTCoreServiceCDK/lib/stacks/MainStack2.ts",
            "/opt/workplace/ATVDeviceRegistry2/src/ATVDeviceRegistryCDKv2/lib/Vpcs3.ts",
            # A mixed-case stand-in for the macOS per-user temp directory, which
            # the separator ceiling saves on every platform. The real shape is
            # pinned by the macOS-host tests below.
            "/var/folders/6r/qKz9XyT3wLmNp7vB2cQ4hJ8000gn/T/screenshot.png",
            "/Users/Someone/Projects/DeepCamelCaseFolder/AnotherCamelFolder/SomeComponentName.ts",
            "/srv/build/src/main/java/com/Example/Service2/FooBarBazClas1/Handler9.java",
            "/mnt/data/RepoName2/PackageNameCDK/lib/config/RegionConfig3/UsEast1Props.ts",
            "/srv/app/BuildArtifacts9/SubProjectCore/GeneratedSources2/ModelTypes4.ts",
            "/private/var/db/CryptexStore2/StagedCryptexes/OsVariant3/PayloadRoot9",
            "/usr/lib/NodeModules2/SomePackageName/DistBundles3/EsmChunkNames9.mjs",
            # A '+' in a component is ordinary: the ceiling counts separators, so it
            # needs no base64-alphabet carve-out.
            "/usr/include/c++/v1/LongCamelNameHere2/AnotherCamelName3/ThirdName4",
            # The root name is ordinary too: nothing here consults a list of roots,
            # so a path under an unusual mount is covered like any other.
            "/data/scratch/BuildRoot2/SubPackageCore/GeneratedModels3/TypeDefs4.ts",
            # Relative, and long enough to be one run.
            "src/main/java/com/Example/Service2/FooBarBazClas1/HandlerImpl9.java",
        ],
    )
    def test_camelcase_path_survives(self, path: str) -> None:
        result, warnings = redact_credentials(path)
        assert result == path, f"path over-redacted: {path!r}"
        assert not warnings

    def test_the_reported_path_is_still_openable(self) -> None:
        """The end-to-end symptom: the redacted string is what the viewer sends.

        A tag in place of the path is not a display glitch -- it is the value the
        file-read request carries, so the chip can never resolve. Assert the two
        properties a consumer needs, not only equality.
        """
        path = (
            "/Volumes/workplace/TRAM/QuickProp2/src/ATVTramQuickPropCDK/lib/config/consumerVpcs.ts"
        )
        result, _ = redact_credentials(path)
        assert REDACTED_CREDENTIAL_TAG not in result
        assert result.startswith("/") and result.endswith(".ts")

    # ── the macOS per-user directory, in its real shape ──

    # ``confstr`` ids as macOS generates them: a 2-character bucket and a
    # 30-character name of lowercase letters and digits with no vowel, ending in
    # the encoded uid. The shape is what matters: a mixed-case or shorter
    # stand-in clears the heuristic on its own and would pin nothing.
    DARWIN_USER_DIR_IDS = (
        ("zz", "pq7mtk933xwbn58cmrlt6hv40000gn"),
        ("6r", "8b2dmqf94w3bb1m3dqx6h6h40000gn"),
    )

    @staticmethod
    def _darwin_root(bucket: str, name: str) -> str:
        return f"/var/folders/{bucket}/{name}/T"

    @staticmethod
    def _as_host(monkeypatch: pytest.MonkeyPatch, host_id: str | None) -> None:
        """Make *host_id* the directory id the OS reports; None is "not macOS"."""
        from kiro_crew.security import redaction as redaction_mod

        monkeypatch.setattr(redaction_mod, "_host_darwin_user_dir_id", lambda: host_id)

    @staticmethod
    def _produced_spool_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
        """The spool-relative path ``ComputerUseService`` writes a screenshot to.

        Produced by the real spooler rather than spelled here, so the directory
        name and the ``shot-<ms>-<random>.jpeg`` file name are the shipped ones.
        """
        from kiro_crew.computer_use import service as service_mod
        from kiro_crew.computer_use.types import AppRef, Snapshot

        monkeypatch.setattr(service_mod.tempfile, "gettempdir", lambda: str(tmp_path))
        snap = Snapshot(
            app=AppRef(name="A", pid=1, bundle_id="com.acme.a", window_id=7),
            elements=(),
            captured_at=0.0,
            image_jpeg=b"\xff\xd8\xff\xd9",
            image_width=1,
            image_height=1,
        )
        produced = service_mod.ComputerUseService()._persist_image(snap).image_path
        assert produced, "the spooler must have written the frame"
        return Path(produced).relative_to(tmp_path).as_posix()

    def test_the_darwin_fixtures_have_the_real_shape(self) -> None:
        from kiro_crew.security import redaction as redaction_mod

        for bucket, name in self.DARWIN_USER_DIR_IDS:
            assert re.fullmatch(r"[a-z0-9]{2}", bucket)
            assert re.fullmatch(r"[a-z0-9]{30}", name)
            assert name.endswith("0000gn")
            assert not set(name) & set("aeiou")
            # And it is an id ``confstr`` could have answered with.
            match = redaction_mod._DARWIN_USER_TEMP_DIR_RE.match(f"/var/folders/{bucket}/{name}/T/")
            assert match and match.group("id") == f"{bucket}/{name}"

    def test_the_produced_screenshot_path_survives_on_its_own_host(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The reported symptom: the model echoes the path and the image renders.

        Checked in every form the path reaches the redactor in: bare, resolved
        through ``/private``, as the markdown image the agent prompt asks for,
        and as the tool result's own ``Screenshot:`` line.
        """
        from kiro_crew.computer_use.types import SCREENSHOT_DIR_NAME

        spooled = self._produced_spool_path(tmp_path, monkeypatch)
        assert spooled.startswith(f"{SCREENSHOT_DIR_NAME}/shot-")
        for bucket, name in self.DARWIN_USER_DIR_IDS:
            self._as_host(monkeypatch, f"{bucket}/{name}")
            path = f"{self._darwin_root(bucket, name)}/{spooled}"
            for text in (
                path,
                f"/private{path}",
                f"![screenshot]({path})",
                f"Screenshot: {path}",
            ):
                assert redact_credentials(text) == (text, []), text

    def test_the_cache_dir_and_an_underscore_bucket_survive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _, name = self.DARWIN_USER_DIR_IDS[0]
        for host_id, path in (
            (f"zz/{name}", f"/var/folders/zz/{name}/C/com.apple.QuickLook.thumbnailcache/index"),
            (f"_w/{name}", f"/var/folders/_w/{name}/T/kirocrew-computer-shots/shot-1.jpeg"),
        ):
            self._as_host(monkeypatch, host_id)
            assert redact_credentials(path) == (path, []), path

    @pytest.mark.parametrize(
        "letter",
        ["T", "C"],
    )
    @pytest.mark.parametrize(
        "tail",
        [
            # Shapes a real temp dir carries: an mkdtemp ``tmpXXXXXXXX`` dir (the
            # 24-byte overlap floor the exemption is set to), a UUID subdir,
            # macOS's TemporaryItems and a short CamelCase name.
            "/tmpab12cd34/x.txt",
            "/3F2504E0-4F89-11D3-9A0C-0305E82C3301/x",
            "/TemporaryItems/x",
            "/A1B2C3D4/x",
        ],
    )
    def test_a_benign_temp_path_survives_on_its_host(
        self, letter: str, tail: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Benign temp paths whose only key-shaped windows sit over the host id.

        Each window on these overlaps the withheld id by at least the exempt
        bound, so the exemption spares it and the whole path survives untouched.
        """
        for bucket, name in self.DARWIN_USER_DIR_IDS:
            self._as_host(monkeypatch, f"{bucket}/{name}")
            text = f"/var/folders/{bucket}/{name}/{letter}{tail}"
            assert redact_credentials(text) == (text, []), text

    def test_without_a_host_id_the_same_path_is_redacted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Nothing is withheld off macOS, and the fixtures really trip the heuristic.

        This is also what keeps the tests above from passing vacuously: these
        ids are the shape the heuristic matches.
        """
        self._as_host(monkeypatch, None)
        for bucket, name in self.DARWIN_USER_DIR_IDS:
            path = f"{self._darwin_root(bucket, name)}/kirocrew-computer-shots/shot-1.jpeg"
            result, warnings = redact_credentials(path)
            assert result != path, path
            assert warnings

    def test_an_id_that_is_not_the_hosts_is_scanned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Only the id the OS reported is withheld, never any string of its shape.

        In free text the id's bytes are the writer's to choose, and a chosen id
        plus a few bytes after ``/T`` is a key-shaped window the split would give
        up. Another id -- another user's, or one composed to carry a window -- is
        therefore judged exactly as it would be with no exemption at all.
        """
        (host_bucket, host_name), (bucket, name) = self.DARWIN_USER_DIR_IDS
        path = f"{self._darwin_root(bucket, name)}/kirocrew-computer-shots/shot-1.jpeg"
        self._as_host(monkeypatch, None)
        canonical = redact_credentials(path)
        self._as_host(monkeypatch, f"{host_bucket}/{host_name}")
        assert redact_credentials(path) == canonical
        assert canonical[0] != path

    @pytest.mark.parametrize(
        "label,shape",
        [
            ("key as a file in the temp dir", "{root}/{key}"),
            ("key with an extension", "{root}/{key}.txt"),
            ("key deeper in the temp dir", "{root}/kirocrew-computer-shots/{key}"),
            ("key in the markdown image form", "![shot]({root}/{key})"),
            # No exemption applies: the glued key means ``T`` does not end its component.
            ("key glued to the directory letter", "{root}{key}"),
            # No exemption applies: with the key glued on, the prefix does not start a path.
            ("key glued before the prefix", "{key}{root}/x"),
            ("key before the prefix across a slash", "{key}/{root}/x"),
        ],
    )
    def test_a_key_next_to_the_temp_dir_is_still_redacted(
        self, label: str, shape: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bucket, name = self.DARWIN_USER_DIR_IDS[0]
        self._as_host(monkeypatch, f"{bucket}/{name}")
        root = self._darwin_root(bucket, name)
        for key in (_AWS_EXAMPLE_KEY, _ALT_SLASH_KEY, _NO_SLASH_KEY):
            result, warnings = redact_credentials(shape.format(root=root, key=key))
            assert key not in result, f"{label}: key leaked"
            assert warnings, label

    def test_only_the_piece_holding_the_key_is_redacted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The id is withheld from the scan, so it is not what a hit replaces."""
        bucket, name = self.DARWIN_USER_DIR_IDS[0]
        self._as_host(monkeypatch, f"{bucket}/{name}")
        result, _ = redact_credentials(f"{self._darwin_root(bucket, name)}/{_AWS_EXAMPLE_KEY}")
        assert result == f"/var/folders/{bucket}/{name}{REDACTED_CREDENTIAL_TAG}"

    @staticmethod
    def _edge_key(name: str, shared: int) -> str:
        """A 40-char ``_looks_like_secret_key`` key that reuses *shared* id bytes.

        The key's first *shared* bytes are the host id ``name``'s last *shared*
        bytes, then ``/T/``, so when it is glued right after ``{bucket}/{name}``
        minus those bytes the id regex still matches and a key-shaped window
        begins inside the id, sharing only those bytes in place. A seeded search
        fills the rest until the heuristic accepts, which is deterministic.
        """
        from kiro_crew.security import redaction as redaction_mod

        head = name[-shared:] + "/T/"
        rng = random.Random(f"edge-key-{name}-{shared}")
        alphabet = string.ascii_letters + string.digits
        for _ in range(200_000):
            key = head + "".join(rng.choice(alphabet) for _ in range(_SECRET_KEY_LEN - len(head)))
            if redaction_mod._looks_like_secret_key(key):
                return key
        raise AssertionError("no key-shaped tail found")

    @pytest.mark.parametrize("shared", [1, 3])
    def test_a_key_sharing_the_ids_tail_is_still_redacted(
        self, shared: int, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GPT 5.6's shape: a key reusing a few id bytes is below the exempt bound.

        The window begins at the key's first byte, which is the id's last byte,
        so it shares only ``shared`` bytes with the withheld id -- far under the
        24-byte exemption -- and must still redact. ``shared=1`` is the reported
        ``<last-id-byte>/T/`` case; ``shared=3`` pins that a three-byte overlap
        is judged too.
        """
        from kiro_crew.security import redaction as redaction_mod

        bucket, name = self.DARWIN_USER_DIR_IDS[0]
        key = self._edge_key(name, shared)
        assert redaction_mod._looks_like_secret_key(key)
        # Glue the key where its leading reused bytes complete the id, so the id
        # regex still matches ``{bucket}/{name}`` ending in ``/T``.
        text = f"/var/folders/{bucket}/{name[:-shared]}" + key
        self._as_host(monkeypatch, f"{bucket}/{name}")
        assert redaction_mod._darwin_user_dir_ids(text), "the id must still be found"
        result, warnings = redact_credentials(text)
        assert key[len(name[-shared:]) :] not in result, "the key tail leaked"
        assert warnings
        assert result.startswith(f"/var/folders/{bucket}/{name}")

    def test_a_key_under_the_temp_dir_is_judged_as_on_any_other_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Withholding the id never removes a verdict on a real key.

        Every key -- including the separator-heavy ones the ceiling's accepted
        residual lets through when glued into a run -- that is redacted under an
        ordinary directory, where no exemption is near it, is still redacted
        under the temp dir. The id exemption can only ADD survival for a window
        that shares most of its bytes with the host id, never remove a verdict a
        real key earns on its own.
        """
        bucket, name = self.DARWIN_USER_DIR_IDS[0]
        self._as_host(monkeypatch, f"{bucket}/{name}")
        root = self._darwin_root(bucket, name)
        for key in (_AWS_EXAMPLE_KEY, _ALT_SLASH_KEY, _NO_SLASH_KEY, *self.SEPARATOR_HEAVY_KEYS):
            under_temp = REDACTED_CREDENTIAL_TAG in redact_credentials(f"{root}/{key}")[0]
            elsewhere = REDACTED_CREDENTIAL_TAG in redact_credentials(f"/srv/ci/tt/{key}")[0]
            assert under_temp or not elsewhere, key

    @pytest.mark.parametrize(
        "label,path",
        [
            ("T not ending its component", "/var/folders/zz/{name}/Tevil{tail}"),
            ("another directory letter", "/var/folders/zz/{name}/X{tail}"),
            ("the prefix does not start a path", "/Users/x/var/folders/zz/{name}/T{tail}"),
            ("a character glued before the prefix", "X/var/folders/zz/{name}/T{tail}"),
            ("a doubled slash before the prefix", "/srv//var/folders/zz/{name}/T{tail}"),
            ("a file URL", "file:///var/folders/zz/{name}/T{tail}"),
        ],
    )
    def test_a_look_alike_gets_the_canonical_verdict(
        self, label: str, path: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The host's id outside the path grammar is scanned whole.

        Asserted as an identity with the no-host result, and each look-alike
        trips the heuristic, so the identity cannot hold merely because nothing
        was found.
        """
        _, name = self.DARWIN_USER_DIR_IDS[0]
        text = path.format(name=name, tail="/kirocrew-computer-shots/shot-1.jpeg")
        self._as_host(monkeypatch, None)
        canonical = redact_credentials(text)
        self._as_host(monkeypatch, f"zz/{name}")
        assert redact_credentials(text) == canonical, label
        assert canonical[0] != text, f"{label}: the look-alike must trip the heuristic"

    @pytest.mark.parametrize(
        "label,shape",
        [
            ("at the end of the text", "TMPDIR={root}"),
            ("followed by a newline", "{root}\n"),
            ("as a JSON string value", '{{"tmp": "{root}"}}'),
            ("inside a PosixPath repr", "PosixPath('{root}')"),
            ("as a call argument", "print({root})"),
            ("followed by a space", "{root} x"),
            # Pins the rule as a complement of the run alphabet, not a list of
            # accepted delimiters: ``|`` is in neither.
            ("followed by a pipe", "{root}|x"),
            # The byte after the letter ends the run, so these are the bare root
            # followed by another run, and the prefix and ``/T`` pieces are each
            # shorter than one key.
            ("T followed by an underscore", "{root}_evil/kirocrew-computer-shots/shot-1.jpeg"),
            ("T followed by a hyphen", "{root}-evil/kirocrew-computer-shots/shot-1.jpeg"),
            ("T followed by a dot", "{root}.evil/kirocrew-computer-shots/shot-1.jpeg"),
        ],
    )
    def test_a_bare_temp_root_survives_whatever_ends_it(
        self, label: str, shape: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A byte outside the run alphabet after the directory letter ends the run.

        ``print(tempfile.gettempdir())``, a JSON dump and a ``PosixPath`` repr all
        show the root followed by something other than ``/`` or the end of the
        text, and each is the same two-byte ``/T`` piece once the id is withheld.
        """
        for bucket, name in self.DARWIN_USER_DIR_IDS:
            self._as_host(monkeypatch, f"{bucket}/{name}")
            text = shape.format(root=self._darwin_root(bucket, name))
            assert redact_credentials(text) == (text, []), f"{label}: {text!r}"

    @pytest.mark.parametrize(
        "label,shape",
        [
            ("key in the next run after an underscored component", "{root}_evil/{key}"),
            ("key glued after an underscore", "{root}_{key}"),
        ],
    )
    def test_a_key_after_the_root_and_a_run_break_is_still_redacted(
        self, label: str, shape: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Ending the run at the letter gives up nothing past it: the key is its own run."""
        bucket, name = self.DARWIN_USER_DIR_IDS[0]
        self._as_host(monkeypatch, f"{bucket}/{name}")
        root = self._darwin_root(bucket, name)
        for key in (_AWS_EXAMPLE_KEY, _ALT_SLASH_KEY, _NO_SLASH_KEY):
            result, warnings = redact_credentials(shape.format(root=root, key=key))
            assert key not in result, f"{label}: key leaked"
            assert result.startswith(root), f"{label}: the root itself must survive"
            assert warnings, label

    # ── the split is entered only for a run the whole-run scan would redact ──

    def test_a_split_run_is_gated_on_its_whole(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Withholding the id can only remove redaction, never add it.

        The tail piece is EXACTLY one key long and carries four separators, so
        on its own it is a standalone token the fragment ceiling does not reach.
        Scanned whole, the run is a fragment and every key-shaped window in it
        holds four or more ``/``, so the ceiling spares it. The verdict with the
        id withheld must be the no-host verdict, which is the base one.
        """
        _, name = self.DARWIN_USER_DIR_IDS[0]
        # An underscored bucket, as in the cache-dir test above: ``_`` ends the run
        # before the bucket letter, so the run is the letter, the name and the tail,
        # and the withheld id reaches the run's start. The one piece left is the tail.
        text = f"/var/folders/_w/{name}/T/kc/S/p0DXy4J2KQC3GfCAwFuLPZSVLmetMYXb"
        tail = text[text.index("/T/") :]
        assert len(tail) == 40 and tail.count("/") == 4
        self._as_host(monkeypatch, None)
        assert redact_credentials(text) == (text, [])
        self._as_host(monkeypatch, f"_w/{name}")
        assert redact_credentials(text) == (text, [])

    def test_a_split_run_that_decodes_to_text_keeps_the_whole_run_verdict(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The encoded-text exclusion reads the whole run's alignment.

        The run base64-decodes to printable text and is left to the decode-and-scan
        pass. The tail piece begins at a different offset modulo four, so cut
        loose it decodes to garbage and its windows read as key-shaped.
        """
        from kiro_crew.security import redaction as redaction_mod

        bucket, name = self.DARWIN_USER_DIR_IDS[0]
        head = f"{self._darwin_root(bucket, name)}/"
        assert len(head) % 4 == 1
        words = (
            b"The quick brown fox jumps over the lazy dog. Pack my box with five dozen "
            b"liquor jugs. How vexingly quick daft zebras jump! Sphinx of black quartz, "
            b"judge my vow. Crazy Frederick bought many very exquisite opal jewels. "
            b"Jinxed wizards pluck ivy from the big quilt."
        )
        # The block of four holding the head's last ``/`` also holds the first
        # three tail characters, so those encode the first two words bytes at the
        # whole run's alignment; the rest is plain base64 of the remainder.
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        first, second = words[0], words[1]
        rest = words[2:]
        rest = rest[: len(rest) - len(rest) % 3]
        tail = (
            alphabet[(first >> 4) & 0xF]
            + alphabet[((first & 0xF) << 2) | (second >> 6)]
            + alphabet[second & 0x3F]
            + base64.b64encode(rest).decode()
        )
        text = head + tail
        assert redaction_mod._decodes_to_printable_text(text)
        assert redaction_mod._contains_bare_secret(text[text.index("/T/") :])
        self._as_host(monkeypatch, None)
        assert redact_credentials(text) == (text, [])
        self._as_host(monkeypatch, f"{bucket}/{name}")
        assert redact_credentials(text) == (text, [])

    @pytest.mark.parametrize("key", [_AWS_EXAMPLE_KEY, _ALT_SLASH_KEY, _NO_SLASH_KEY])
    @pytest.mark.parametrize("prefix", ["", "/private"])
    def test_a_printable_piece_cannot_hide_a_key_in_a_nonprintable_run(
        self, key: str, prefix: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A piece's printable decode must not replace the whole run's verdict."""
        from kiro_crew.security import redaction as redaction_mod

        bucket, name = self.DARWIN_USER_DIR_IDS[0]
        self._as_host(monkeypatch, f"{bucket}/{name}")
        # /T/A occupies one base64 quartet; the filler dominates its printable
        # decode while the host-id prefix shifts the whole run's alignment.
        filler = (
            "A" + base64.b64encode(b"The quick brown fox jumps over the lazy dog. " * 9).decode()
        )
        text = f"{prefix}{self._darwin_root(bucket, name)}/{filler}{key}"
        piece = text[text.index("/T/") :]
        assert redaction_mod._BARE_SECRET_RUN_RE.fullmatch(text)
        assert redaction_mod._looks_like_secret_key(key)
        assert redaction_mod._decodes_to_printable_text(piece)
        assert not redaction_mod._decodes_to_printable_text(text)
        assert redaction_mod._contains_bare_secret(text)
        result, warnings = redact_credentials(text)
        assert key not in result
        assert result.startswith(f"{prefix}/var/folders/{bucket}/{name}")
        assert warnings

    @pytest.mark.parametrize("key", [_AWS_EXAMPLE_KEY, _ALT_SLASH_KEY, _NO_SLASH_KEY])
    def test_benign_filler_keeps_the_root_and_redacts_the_key(
        self, key: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bucket, name = self.DARWIN_USER_DIR_IDS[0]
        self._as_host(monkeypatch, f"{bucket}/{name}")
        root = self._darwin_root(bucket, name)
        result, warnings = redact_credentials(f"{root}/kirocrew-computer-shots/{key}")
        assert key not in result
        assert result.startswith(root)
        assert warnings

    def test_the_host_id_is_what_confstr_reports(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Asked once of the OS; a refusal or an off-grammar answer withholds nothing."""
        from kiro_crew.security import redaction as redaction_mod

        bucket, name = self.DARWIN_USER_DIR_IDS[0]
        calls: list[int] = []

        def answer(value: object) -> Callable[[int], str]:
            def confstr(key: int) -> str:
                calls.append(key)
                if isinstance(value, Exception):
                    raise value
                return str(value)

            return confstr

        read = redaction_mod._host_darwin_user_dir_id
        try:
            with monkeypatch.context() as mp:
                for reported, expected in (
                    (f"/var/folders/{bucket}/{name}/T/", f"{bucket}/{name}"),
                    (f"/private/var/folders/{bucket}/{name}/T/", f"{bucket}/{name}"),
                    ("/tmp/", None),
                    (f"/var/folders/{bucket}/{name}x/T/", None),
                    (OSError(22, "Invalid argument"), None),
                ):
                    read.cache_clear()
                    calls.clear()
                    mp.setattr(redaction_mod.os, "confstr", answer(reported), raising=False)
                    assert read() == expected, reported
                    assert read() == expected
                    assert calls == [redaction_mod._CS_DARWIN_USER_TEMP_DIR], "asked once"
                # Windows: ``os.confstr`` does not exist, which must read as no host
                # id rather than raise out of every redaction of a macOS path.
                read.cache_clear()
                mp.delattr(redaction_mod.os, "confstr", raising=False)
                assert read() is None
                assert redact_credentials("/var/folders/zz/x/T/a")[0] == "/var/folders/zz/x/T/a"
        finally:
            read.cache_clear()

    @pytest.mark.skipif(sys.platform != "darwin", reason="reads the real macOS confstr")
    def test_the_real_temp_dir_survives_on_macos(self) -> None:
        from kiro_crew.security import redaction as redaction_mod

        redaction_mod._host_darwin_user_dir_id.cache_clear()
        host_id = redaction_mod._host_darwin_user_dir_id()
        assert host_id is not None, "confstr(_CS_DARWIN_USER_TEMP_DIR) must report the id"
        path = f"/var/folders/{host_id}/T/kirocrew-computer-shots/shot-1700000000000-ab12cd34.jpeg"
        assert redact_credentials(f"![screenshot]({path})")[0] == f"![screenshot]({path})"

    # ── a standalone key is never subject to the ceiling ──

    # Uniformly random 40-char base64 tokens that the seven gates accept AND that
    # carry more separators than the ceiling -- the population the ceiling would
    # cost if it reached a standalone token. They cover 4 to 8 separators,
    # including a leading one, a trailing one and an adjacent pair.
    SEPARATOR_HEAVY_KEYS = (
        "KSd5/MUOI7pQ/+X/lzj0Ma/DwFo5hMVm6ScMCQUs",
        "dMtmrCnv/fCJ/FcS/N/VWJV/t4OMtde4urD+evIx",
        "/ybCN+5DAYirSIyzpX/f1cjuq5b/mLA4NxO9/3sH",
        "EuaHEF+2RGfJHHMc/r6//y7R0zTqsz/9/PZs6zcj",
        "wu9P3axJ2M/J0fFa/MG/hJ/LP/C7KzMSpSVr5w//",
        "Zy6//Pgqw1X5bzp55Iv/RvJ/y/KSojZIKIlR/umL",
    )

    @pytest.mark.parametrize("key", SEPARATOR_HEAVY_KEYS)
    def test_a_standalone_key_is_redacted_however_many_separators_it_holds(self, key: str) -> None:
        """The ceiling applies to a FRAGMENT, and a standalone key is not one.

        A genuine AWS secret access key is uniformly random base64, so roughly 1
        in 200 of them carries four or more separators. Such a key echoed on its
        own -- in prose, in a JSON array element, after a label, on its own line --
        is a run of exactly ``_SECRET_KEY_LEN`` chars, which is the token somebody
        wrote rather than a window cut out of anything. It must redact whatever its
        separator count, and this is what pins that.
        """
        assert len(key) == _SECRET_KEY_LEN
        assert key.count("/") > _SECRET_MAX_SLASHES, "fixture must exceed the ceiling"
        assert security._looks_like_secret_key(key), "fixture must be key-shaped"
        for label, text in (
            ("standalone", key),
            ("in prose", f"the key is {key} - keep it safe"),
            ("in a JSON array", f'{{"keys": ["{key}"]}}'),
            ("after a label", f"SECRET_ACCESS_KEY={key}"),
        ):
            result, _ = redact_credentials(text)
            assert key not in result, f"{label}: key leaked: {key!r}"

    # ── secrets must still be redacted, in every path context ──

    @pytest.mark.parametrize(
        "label,text",
        [
            ("standalone slash-bearing key", _AWS_EXAMPLE_KEY),
            ("standalone second slash-bearing key", _ALT_SLASH_KEY),
            ("standalone slash-free key", _NO_SLASH_KEY),
            ("key as a path component", f"/srv/ci/keys/{_AWS_EXAMPLE_KEY}"),
            ("second key as a path component", f"/srv/ci/keys/{_ALT_SLASH_KEY}"),
            ("slash-free key as a component", f"/srv/ci/keys/{_NO_SLASH_KEY}"),
            ("key in a URL path", f"https://example.com/v1/data/{_AWS_EXAMPLE_KEY}"),
            ("key with components after it", f"/srv/ci/keys/dir/{_AWS_EXAMPLE_KEY}/more/here"),
            ("key glued after a prefix", f"/srv/ci/keys/pfx{_AWS_EXAMPLE_KEY}"),
            ("key glued before a suffix", f"/srv/ci/keys/{_AWS_EXAMPLE_KEY}sfx"),
            ("key glued on both sides", f"/srv/ci/keys/X{_AWS_EXAMPLE_KEY}X"),
            ("key buried in one component", f"/srv/ci/keys/pfx{_NO_SLASH_KEY}sfx"),
            # A key whose true offset is not where any component begins, and whose
            # component-start window is a word-shaped prefix plus a partial key.
            # A gate on the window's own bytes still classifies the key itself.
            (
                "key glued after a word-shaped prefix",
                f"/aa/bb/cc/loremipsumdolorsitam{_AWS_EXAMPLE_KEY}",
            ),
            (
                "second key glued after a word-shaped prefix",
                f"/aa/bb/cc/loremipsumdolorsitam{_ALT_SLASH_KEY}",
            ),
        ],
    )
    def test_secret_is_still_redacted(self, label: str, text: str) -> None:
        result, warnings = redact_credentials(text)
        assert REDACTED_CREDENTIAL_TAG in result, f"{label}: secret leaked: {text!r}"
        assert warnings, label

    def test_a_key_at_the_ceiling_is_still_found_inside_a_run(self) -> None:
        """The ceiling is inclusive: exactly ``_SECRET_MAX_SLASHES`` separators pass.

        A key-shaped window carrying exactly the ceiling's count, glued into a
        path so the run is a fragment, must still redact. Pins the boundary the
        residual test above sits one past.
        """
        key = "1GQmz9m/Mbpp/8bv4mTvEFNQR/Y8O2C2SSYEDQYD"
        assert len(key) == _SECRET_KEY_LEN
        assert key.count("/") == _SECRET_MAX_SLASHES
        assert security._looks_like_secret_key(key)
        result, warnings = redact_credentials(f"/srv/ci/keys/{key}")
        assert REDACTED_CREDENTIAL_TAG in result
        assert warnings

    # ── the accepted residual, pinned so it is a decision and not a gap ──

    @pytest.mark.parametrize("key", SEPARATOR_HEAVY_KEYS[:2])
    @pytest.mark.parametrize("enclosing", ["/srv/ci/keys/{}", "https://example.com/v1/{}"])
    def test_the_accepted_residual_is_a_separator_heavy_key_glued_into_a_run(
        self, key: str, enclosing: str
    ) -> None:
        """DOCUMENTS AN ACCEPTED LOSS. This asserts what is NOT redacted.

        A key carrying more separators than the ceiling AND glued into a longer run
        is not detected. That is the trade this ceiling makes, and it is asserted
        here so it is a reviewed decision with a name rather than an untested
        corner of the credential-redaction guarantee.

        It cannot be closed at this layer. The benign path the ceiling exists to
        save and the key below are the SAME BYTES to the classifier: both are
        40-char windows over ``[A-Za-z0-9+/]`` carrying several separators that
        clear all seven gates, inside a run longer than one key. Any rule reading
        only the run's bytes that declines the first must decline the second.
        Distinguishing them needs information the run does not carry -- that the
        value is a path FIELD -- and ``redact_credentials`` runs over free-form
        transcript text, which has no such field.

        What bounds the loss is ``is_fragment``: the run must be longer than one
        whole key, so every shape an accidental echo takes is excluded. The
        surviving class needs a key that both carries 4+ separators (0.36% of
        uniformly random keys) and is concatenated to further base64 characters
        with no delimiter.

        If a future change adds a signal that separates the two, this test is the
        one to delete -- deliberately, and with the ceiling's rationale reread.
        """
        text = enclosing.format(key)
        assert key.count("/") > _SECRET_MAX_SLASHES
        assert security._looks_like_secret_key(key), "fixture must be key-shaped"
        result, warnings = redact_credentials(text)
        assert result == text
        assert not warnings

    # ── the two properties that keep the ceiling from being a hole ──

    def test_no_window_of_a_path_run_is_skipped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The ceiling may decline a window; it may not decline to LOOK at one.

        Narrowing which offsets are examined is the other available shape of this
        fix, and it leaves a key whose true offset is not examined undetected.
        This counts classifications: every offset of the run must still reach the
        classifier even though the run is a path and the verdict is False.
        """
        run = "/Volumes/workplace/TRAM/QuickProp2/src/ATVTramQuickPropCDK/lib/config/consumerVpcs"
        seen: list[str] = []
        real = security._looks_like_secret_key

        def counting(token: str) -> bool:
            seen.append(token)
            return real(token)

        monkeypatch.setattr(security, "_looks_like_secret_key", counting)
        assert security._contains_bare_secret(run) is False
        assert len(seen) == len(run) - _SECRET_KEY_LEN + 1
        # And the classifier itself said yes to at least one of them, which is what
        # makes the ceiling -- rather than some other gate -- the thing that saved
        # this path.
        assert any(real(token) for token in seen)

    def test_the_ceiling_is_what_saves_the_reported_path(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Raise the ceiling and the reported path is swallowed again.

        Asserted directly so the benign-path fixtures above cannot silently stop
        depending on the ceiling.
        """
        path = (
            "/Volumes/workplace/TRAM/QuickProp2/src/ATVTramQuickPropCDK/lib/config/consumerVpcs.ts"
        )
        assert redact_credentials(path)[0] == path
        monkeypatch.setattr(security, "_SECRET_MAX_SLASHES", _SECRET_KEY_LEN)
        assert redact_credentials(path)[0] != path

    def test_the_classifier_itself_is_unchanged_by_the_ceiling(self) -> None:
        """``_looks_like_secret_key`` stays a seven-gate predicate on its token.

        The ceiling lives in the slide, not in the classifier, because it is a
        statement about a window's relationship to a longer run rather than about
        the token. A token with many separators is still a secret to the
        classifier, and that is what lets a standalone key keep redacting.
        """
        token = self.SEPARATOR_HEAVY_KEYS[0]
        assert token.count("/") > _SECRET_MAX_SLASHES
        assert security._looks_like_secret_key(token) is True


class TestSecretSlashCapIsTheKnee:
    """Pin the ceiling's value against the real classifier, not a re-implementation.

    The two deep paths below are the ones the seven older gates cannot save. The
    chosen ceiling saves both; one notch looser saves neither. Swapping the
    constant rather than re-implementing the slide is what makes this a test of
    the shipped code.
    """

    PATHS = (
        "/Volumes/workplace/TRAM/QuickProp2/src/ATVTramQuickPropCDK/lib/config/consumerVpcs",
        "/var/folders/6r/qKz9XyT3wLmNp7vB2cQ4hJ8000gn/T/screenshot",
    )

    @pytest.mark.parametrize("path", PATHS)
    def test_the_chosen_ceiling_saves_the_path(
        self, path: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(security, "_SECRET_MAX_SLASHES", _SECRET_MAX_SLASHES)
        assert security._contains_bare_secret(path) is False

    @pytest.mark.parametrize("path", PATHS)
    def test_one_notch_looser_does_not(self, path: str, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(security, "_SECRET_MAX_SLASHES", _SECRET_MAX_SLASHES + 1)
        assert security._contains_bare_secret(path) is True


class TestBareSecretRunLevelFastPath:
    """The run-level fast path must be an optimization ONLY, never a hole.

    ``_contains_bare_secret`` slides a 40-char window byte by byte, so a long
    base64-alphabet run costs one full classification per offset. Two per-window
    gates reject on a property closed under substring -- a missing character
    class (gate 2) and all-hex (gate 3) -- so the whole run can be asked once and
    every window retired. These tests pin both halves of that claim: the fast
    path really fires (a behaviour-only test cannot see it), and it cannot
    swallow a genuine secret hidden inside a long run.
    """

    @staticmethod
    def _count_window_classifications(run: str, monkeypatch: pytest.MonkeyPatch) -> int:
        """Return how many 40-char windows of *run* got fully classified."""
        calls = []
        original = security._looks_like_secret_key

        def counting(token: str) -> bool:
            calls.append(token)
            return original(token)

        monkeypatch.setattr(security, "_looks_like_secret_key", counting)
        security._contains_bare_secret(run)
        return len(calls)

    def test_run_missing_a_char_class_skips_every_window(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # 520 lowercase chars: no window can hold an uppercase char or a digit,
        # so gate 2 rejects all 481 of them. Without the fast path this is 481
        # full classifications; with it, zero.
        run = "abcdefghijklmnopqrstuvwxyz" * 20
        assert len(run) == 520
        assert security._contains_bare_secret(run) is False
        assert self._count_window_classifications(run, monkeypatch) == 0

    def test_all_hex_run_skips_every_window(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # A long mixed-case hex digest passes gate 2 in every window but dies at
        # gate 3 in every window. All-hex is closed under substring, so one
        # whole-run test retires the slide -- 137 classifications become zero.
        run = "0123456789abcdefABCDEF" * 8
        assert len(run) == 176
        assert security._HEX_ONLY_RE.match(run)
        assert security._contains_bare_secret(run) is False
        assert self._count_window_classifications(run, monkeypatch) == 0

    def test_exactly_one_window_run_is_still_classified(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # BOUNDARY: the fast path is gated on `len(run) > _SECRET_KEY_LEN`, so a
        # 40-char run must still reach the classifier.
        #
        # The fixture must FAIL one of the two fast-path gates, or this test
        # cannot detect the boundary being wrong. With 40 lowercase chars: under
        # `>` the fast path is skipped and the sole window is classified (1);
        # under a mutated `>=` the fast path fires, the class check rejects, and
        # nothing is classified (0). A fixture that clears both gates -- an AWS
        # example key, say -- passes either way and pins nothing.
        run = "abcdefghijklmnopqrstuvwxyz" + "abcdefghijklmn"
        assert len(run) == _SECRET_KEY_LEN
        assert not security._has_all_three_char_classes(run)
        assert self._count_window_classifications(run, monkeypatch) == 1

    def test_secret_glued_into_a_long_mixed_run_is_still_found(self) -> None:
        # The fast path must not retire a run that DOES contain a secret. A real
        # key glued to base64 padding on both sides makes a 60-char run whose
        # only qualifying window is at a non-zero offset.
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        run = "abc123XYZ/" + secret + "0123456789"
        assert len(run) > _SECRET_KEY_LEN
        assert security._contains_bare_secret(run) is True
        result, warnings = redact_credentials(f"token={run}")
        assert secret not in result
        assert warnings

    def test_run_with_all_three_classes_is_fully_slid(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # NEGATIVE CONTROL: the fast path may skip a run only when it can PROVE
        # no window qualifies. This run holds all three classes and is not
        # all-hex, so every one of its 21 windows must still be classified --
        # 60 - 40 + 1 == 21. (Beware fixtures like "aB3" * 30: a, B and 3 are
        # all hex digits, so that run is all-hex and is legitimately skipped.)
        run = "Zz9" * 20
        assert len(run) == 60
        assert not security._HEX_ONLY_RE.match(run)
        assert security._contains_bare_secret(run) is False
        assert self._count_window_classifications(run, monkeypatch) == 21


class TestCharClassHelperMatchesTheThreeScanDefinition:
    """``_has_all_three_char_classes`` replaced three ``any()`` scans.

    The single-pass early-exit loop must agree with the definition it replaced on
    every input, including the elif-chain cases where one character could be
    considered for more than one class.
    """

    @staticmethod
    def _reference(text: str) -> bool:
        return (
            any(ch.islower() for ch in text)
            and any(ch.isupper() for ch in text)
            and any(ch.isdigit() for ch in text)
        )

    @pytest.mark.parametrize(
        "text",
        [
            "",
            "a",
            "A",
            "1",
            "aA1",
            "1Aa",
            "A1a",
            "aaaaaaaa",
            "AAAAAAAA",
            "12345678",
            "aaaa1111",
            "AAAA1111",
            "aaaaAAAA",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            "0123456789abcdef0123456789abcdef01234567",
            "+/+/+/+/",
            "MASSE",
            "straße",
        ],
    )
    def test_agrees_with_reference_on_representative_shapes(self, text: str) -> None:
        assert security._has_all_three_char_classes(text) is self._reference(text)

    def test_agrees_with_reference_across_a_random_corpus(self) -> None:
        rng = random.Random(20260810)
        alphabet = string.ascii_letters + string.digits + "+/=-_ "
        for _ in range(4000):
            text = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 44)))
            assert security._has_all_three_char_classes(text) is self._reference(
                text
            ), f"disagreement on {text!r}"


class TestSecretGateOrderIsCostOrdered:
    """The gate ORDER is the point of the cost ordering, so pin it directly.

    ``TestSecretGateOrderIsVerdictNeutral`` cannot pin it: a conjunction of pure
    predicates is order-independent by construction, so no corpus can witness a
    reordering. Reverting the gates to entropy-first therefore passes every
    verdict test while silently undoing the optimisation. These tests count which
    gates get EVALUATED, which is the only observable that distinguishes one
    order from another.
    """

    @staticmethod
    def _counting_classify(token: str, monkeypatch: pytest.MonkeyPatch) -> dict[str, int]:
        """Classify *token*, counting calls to each expensive gate."""
        counts = {"entropy": 0, "decode": 0}
        real_entropy = security._shannon_entropy
        real_decode = security._decodes_to_printable_text

        def entropy(t: str) -> float:
            counts["entropy"] += 1
            return real_entropy(t)

        def decode(t: str) -> bool:
            counts["decode"] += 1
            return real_decode(t)

        monkeypatch.setattr(security, "_shannon_entropy", entropy)
        monkeypatch.setattr(security, "_decodes_to_printable_text", decode)
        security._looks_like_secret_key(token)
        return counts

    def test_a_structural_rejection_never_pays_for_entropy_or_decode(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # "aB3/" * 10 is 40 chars, holds all three classes, is not all-hex, and
        # has a vowel ratio of 0.5 -- so a structural gate rejects it. With the
        # structural gates first, neither expensive gate is ever called. Revert
        # to entropy-first and entropy is called, failing this test. That revert
        # is exactly the mutation no verdict-based test can catch.
        token = "aB3/" * 10
        assert len(token) == _SECRET_KEY_LEN
        assert security._has_all_three_char_classes(token)
        assert not security._HEX_ONLY_RE.match(token)
        counts = self._counting_classify(token, monkeypatch)
        assert counts == {"entropy": 0, "decode": 0}, (
            "a token rejected by a structural gate must not pay for entropy or "
            f"decode; got {counts}"
        )

    def test_decode_is_last_so_an_entropy_rejection_never_pays_for_it(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # "Zz9" * 20 clears both structural gates but fails the entropy floor
        # (1.58 < 4.3). With decode last it is never called; move decode ahead of
        # entropy and this fails.
        token = ("Zz9" * 20)[:_SECRET_KEY_LEN]
        assert not security._lowercase_run_exceeds(token, security._SECRET_MAX_LOWER_RUN)
        assert security._vowel_ratio(token) <= security._SECRET_MAX_VOWEL_RATIO
        assert security._shannon_entropy(token) < security._SECRET_ENTROPY_MIN
        counts = self._counting_classify(token, monkeypatch)
        assert counts["entropy"] == 1, f"entropy should be reached: {counts}"
        assert counts["decode"] == 0, f"decode must run after entropy: {counts}"

    def test_a_real_key_still_pays_for_every_gate(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # The pass-through case: a genuine key clears all gates, so every gate
        # runs exactly once. This is what proves the cheap gates are not
        # short-circuiting a real secret away from the expensive checks.
        counts = self._counting_classify("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", monkeypatch)
        assert counts == {"entropy": 1, "decode": 1}


class TestSecretGateOrderIsVerdictNeutral:
    """Gates 4-7 are ordered by measured cost, so the order must not change verdicts.

    Every one of those gates is a pure predicate whose failure returns False, so
    reordering them can only change WHICH gate reports a rejection -- never
    whether the token is rejected. That is the property this class pins, because
    a reorder that silently changed one verdict in the redaction path would mean
    either a leaked credential or a corrupted benign output.
    """

    # Shapes chosen to exercise each gate as the deciding one: real keys, base64
    # blobs, JWT segments, file paths, camelCase identifiers, hex digests, prose.
    SOURCES = (
        "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4ifQ",
        "src/kiro_crew/security/redaction/Handler2/Manager3/Factory4/Builder5x",
        "getUserAccountManagerFactory2BuilderHelperImpl3ServiceProvider4x",
        "0123456789abcdefABCDEF0123456789abcdefAB",
        "TheGatewayRestoredTheSessionAndReplayed12ToolCallsSeeSecurityPy",
        "aB3/" * 24,
        "Zz9" * 20,
        # base64 of printable ASCII: the encoded-text-blob shape gate 7 exists to
        # exclude. This token clears gates 1-6 (vowel 0.079, no long lowercase
        # run, entropy 4.48) and is rejected ONLY by the decode gate, which is
        # what lets this corpus detect that gate being dropped or bypassed.
        "dFlnal9tVWgsQmVsMzFpRWwyaHBDaFlnQ2ZyTDFz",
    )

    @staticmethod
    def _reference(token: str) -> bool:
        """The classifier with gates 4-7 in every order, evaluated exhaustively.

        Rather than hard-code one alternative ordering, evaluate all four gates
        independently and AND them. Any ordering of short-circuiting checks must
        agree with the unordered conjunction.
        """
        if len(token) != _SECRET_KEY_LEN:
            return False
        if not security._has_all_three_char_classes(token):
            return False
        if security._HEX_ONLY_RE.match(token):
            return False
        return (
            security._vowel_ratio(token) <= security._SECRET_MAX_VOWEL_RATIO
            and not security._lowercase_run_exceeds(token, security._SECRET_MAX_LOWER_RUN)
            and security._shannon_entropy(token) >= security._SECRET_ENTROPY_MIN
            and not security._decodes_to_printable_text(token)
        )

    def _windows(self) -> list[str]:
        out = []
        for src in self.SOURCES:
            for i in range(max(1, len(src) - _SECRET_KEY_LEN + 1)):
                out.append(src[i : i + _SECRET_KEY_LEN])
        rng = random.Random(20260811)
        b64 = string.ascii_letters + string.digits + "+/"
        out += ["".join(rng.choice(b64) for _ in range(40)) for _ in range(500)]
        return out

    def test_ordered_classifier_matches_the_unordered_conjunction(self) -> None:
        windows = self._windows()
        assert len(windows) > 500
        for w in windows:
            assert security._looks_like_secret_key(w) is self._reference(
                w
            ), f"gate order changed the verdict for {w!r}"

    def test_the_corpus_actually_exercises_every_gate(self) -> None:
        # A verdict-equivalence test over a corpus that never reaches gates 4-7
        # would pass no matter how they were ordered. Prove the corpus bites.
        reached = {"vowel": 0, "lower": 0, "entropy": 0, "decode": 0, "passed": 0}
        for w in self._windows():
            if len(w) != _SECRET_KEY_LEN or not security._has_all_three_char_classes(w):
                continue
            if security._HEX_ONLY_RE.match(w):
                continue
            if security._lowercase_run_exceeds(w, security._SECRET_MAX_LOWER_RUN):
                reached["lower"] += 1
            elif security._vowel_ratio(w) > security._SECRET_MAX_VOWEL_RATIO:
                reached["vowel"] += 1
            elif security._shannon_entropy(w) < security._SECRET_ENTROPY_MIN:
                reached["entropy"] += 1
            elif security._decodes_to_printable_text(w):
                reached["decode"] += 1
            else:
                reached["passed"] += 1
        for gate in ("vowel", "lower", "entropy", "decode", "passed"):
            assert reached[gate] > 0, f"corpus never exercised gate {gate}: {reached}"

    def test_a_real_secret_key_still_redacts_end_to_end(self) -> None:
        secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        result, warnings = redact_credentials(f"AWS_SECRET={secret} keep this prose")
        assert secret not in result
        assert warnings
        assert "keep this prose" in result


class TestShannonEntropyIsBitIdentical:
    """``_shannon_entropy`` precomputes its terms, and must not move a single bit.

    The value feeds a ``>= _SECRET_ENTROPY_MIN`` comparison in
    :func:`~kiro_crew.security._looks_like_secret_key`, so it decides whether a
    token is redacted. That makes ``math.isclose`` the WRONG assertion for this
    function: a drift small enough to pass a tolerance check is still large
    enough to flip the comparison for a token sitting on the boundary, and a flip
    in the permissive direction leaks a credential verbatim. So these tests
    compare IEEE-754 bit patterns via :func:`struct.pack`, which fails on a
    one-ULP difference and cannot be satisfied by "close enough".

    :meth:`_oracle` holds the pre-optimisation implementation verbatim. Keeping it
    here rather than deleting it is the point: the optimisation's whole claim is
    equality with THAT expression, so the claim needs the expression to still
    exist somewhere executable.
    """

    # Character counts of the two 40-char tokens whose entropy sits closest to
    # 4.3 from either side. Entropy depends only on the MULTISET OF COUNTS, so a
    # partition of 40 pins the value exactly and any token realising it has that
    # entropy. Searching every partition of 40 (restricted to at most one
    # base64-alphabet character each) found these two as the nearest achievable
    # neighbours of the threshold -- 4.3012... above and 4.2964... below.
    _NEAREST_ABOVE_COUNTS = (5, 5, 5, 2, 2, 2) + (1,) * 19
    _NEAREST_BELOW_COUNTS = (3, 3, 3, 3) + (2,) * 11 + (1,) * 6

    _ALPHABET = string.ascii_letters + string.digits + "+/"

    @staticmethod
    def _oracle(token: str) -> float:
        """The implementation from before the term table, character for character."""
        if not token:
            return 0.0
        counts = Counter(token)
        length = len(token)
        return -sum((c / length) * math.log2(c / length) for c in counts.values())

    @staticmethod
    def _bits(value: float) -> bytes:
        """Return *value*'s IEEE-754 bytes, so ``-0.0`` and ``0.0`` differ."""
        return struct.pack("<d", value)

    @classmethod
    def _realize(cls, counts: tuple[int, ...], shuffle_seed: int | None = None) -> str:
        """Build a token whose character counts are exactly *counts*."""
        chars: list[str] = []
        for index, count in enumerate(counts):
            chars.extend(cls._ALPHABET[index] * count)
        if shuffle_seed is not None:
            random.Random(shuffle_seed).shuffle(chars)
        return "".join(chars)

    @classmethod
    def _corpus(cls) -> list[str]:
        """Tokens spanning every shape this function is asked about, and then some."""
        tokens: list[str] = []

        # 1. The gate-order corpus: real keys, JWT segments, paths, identifiers,
        #    hex digests, prose, base64 blobs -- every 40-char window of each.
        for source in TestSecretGateOrderIsVerdictNeutral.SOURCES:
            for i in range(max(1, len(source) - _SECRET_KEY_LEN + 1)):
                tokens.append(source[i : i + _SECRET_KEY_LEN])

        # 2. Random base64-alphabet windows, the shape a real secret has.
        rng = random.Random(20260901)
        tokens += [
            "".join(rng.choice(cls._ALPHABET) for _ in range(_SECRET_KEY_LEN)) for _ in range(500)
        ]

        # 3. ADVERSARIAL: the nearest-to-threshold tokens from both sides, each in
        #    its natural order plus seeded shuffles. The shuffles vary the
        #    first-occurrence order that drives the summation sequence, so a
        #    rewrite that canonicalised or sorted the counts would have to survive
        #    many different orders of the same addends.
        for counts in (cls._NEAREST_ABOVE_COUNTS, cls._NEAREST_BELOW_COUNTS):
            tokens.append(cls._realize(counts))
            tokens += [cls._realize(counts, seed) for seed in range(16)]

        # 4. Degenerate and boundary shapes: empty, single character, all-identical
        #    (whose entropy is -0.0, a distinct bit pattern from 0.0), two
        #    characters, the whole alphabet once each, non-ASCII, and an astral
        #    character whose UTF-16 surrogate pair must not be counted as two.
        tokens += [
            "",
            "a",
            "a" * _SECRET_KEY_LEN,
            "ab" * 20,
            cls._ALPHABET,
            "h\u00e9llo w\u00f6rld",
            "\U0001f511" * 8,
        ]

        # 5. Lengths on both sides of the one length the table covers, so both the
        #    table path and the inline fallback are exercised.
        for length in (1, 2, 3, 39, 40, 41, 255, 256, 257, 1024):
            tokens.append("".join(cls._ALPHABET[i % len(cls._ALPHABET)] for i in range(length)))
            tokens.append("z" * length)

        return tokens

    def test_every_token_is_bit_identical_to_the_pre_table_implementation(self) -> None:
        corpus = self._corpus()
        assert len(corpus) > 500, "corpus collapsed; the rest of this class proves nothing"
        for token in corpus:
            got = security._shannon_entropy(token)
            want = self._oracle(token)
            assert self._bits(got) == self._bits(want), (
                f"entropy drifted for {token!r}: got {got!r} "
                f"({self._bits(got).hex()}) want {want!r} ({self._bits(want).hex()})"
            )

    def test_no_token_in_the_corpus_changes_side_of_the_redaction_threshold(self) -> None:
        # Bit-identity implies this, but assert it directly: this is the property
        # a leak would violate, and it survives a future refactor that relaxes the
        # bit-level assertion above.
        for token in self._corpus():
            new_side = security._shannon_entropy(token) >= security._SECRET_ENTROPY_MIN
            old_side = self._oracle(token) >= security._SECRET_ENTROPY_MIN
            assert new_side is old_side, f"redaction verdict flipped for {token!r}"

    def test_the_corpus_straddles_the_threshold_from_both_sides(self) -> None:
        # A bit-identity test over a corpus that never approaches 4.3 would pass
        # no matter how the boundary behaved. Prove the corpus bites.
        values = [security._shannon_entropy(token) for token in self._corpus()]
        threshold = security._SECRET_ENTROPY_MIN
        above = [v for v in values if v >= threshold]
        below = [v for v in values if v < threshold]
        assert above, "corpus has no token at or above the threshold"
        assert below, "corpus has no token below the threshold"
        # And the nearest neighbours really are within a few thousandths of it.
        # Those two bounds are the MEASURED gaps: no 40-char token can sit closer
        # to 4.3 than 1.21e-3 above or 3.57e-3 below, because entropy at a fixed
        # length takes only the discrete values the partitions of that length
        # allow. Tightening either bound past its gap would assert an input that
        # does not exist.
        assert min(above) - threshold < 2e-3, f"closest token above is {min(above)!r}"
        assert threshold - max(below) < 4e-3, f"closest token below is {max(below)!r}"

    def test_the_nearest_neighbour_tokens_land_on_opposite_sides(self) -> None:
        threshold = security._SECRET_ENTROPY_MIN
        above = security._shannon_entropy(self._realize(self._NEAREST_ABOVE_COUNTS))
        below = security._shannon_entropy(self._realize(self._NEAREST_BELOW_COUNTS))
        assert above >= threshold, f"expected {above!r} at or above {threshold}"
        assert below < threshold, f"expected {below!r} below {threshold}"

    def test_the_corpus_exercises_both_the_table_and_the_fallback(self) -> None:
        # The two code paths must both be reached, or the fallback is untested and
        # the table branch is a silent behaviour change for every other length.
        lengths = {len(token) for token in self._corpus()}
        assert _SECRET_KEY_LEN in lengths, lengths
        assert any(n != _SECRET_KEY_LEN for n in lengths), lengths

    def test_an_all_identical_token_keeps_its_negative_zero(self) -> None:
        # Every term is 1.0 * log2(1.0) == 0.0, and negating the sum yields -0.0.
        # math.isclose and == both treat -0.0 as 0.0, so only the bit pattern can
        # tell that the sign was preserved.
        value = security._shannon_entropy("a" * _SECRET_KEY_LEN)
        assert self._bits(value) == self._bits(-0.0)
        assert self._bits(value) != self._bits(0.0)

    def test_an_empty_token_is_positive_zero(self) -> None:
        # The early return is a literal 0.0, not a negated sum, so its sign
        # differs from the all-identical case above. Pin both.
        assert self._bits(security._shannon_entropy("")) == self._bits(0.0)

    def test_each_table_entry_equals_the_inline_expression_it_replaced(self) -> None:
        # The table is only a precomputation if every entry is what the inline
        # expression would have produced. The table covers exactly one length, so
        # check it exhaustively.
        table = security._ENTROPY_TERMS_KEY_LEN
        assert len(table) == _SECRET_KEY_LEN + 1
        for count in range(1, _SECRET_KEY_LEN + 1):
            want = (count / _SECRET_KEY_LEN) * math.log2(count / _SECRET_KEY_LEN)
            detail = f"term {count} of {_SECRET_KEY_LEN}: {table[count]!r} != {want!r}"
            assert self._bits(table[count]) == self._bits(want), detail

    def test_the_table_covers_the_only_length_the_gate_can_ask_about(self) -> None:
        # The table is built for one length rather than parameterised, so that
        # length must be the one gate 1 admits. If _SECRET_KEY_LEN ever changes
        # without the table following, every 40-char token would silently take the
        # inline fallback and the optimisation would be dead code.
        token = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        assert len(token) == _SECRET_KEY_LEN
        assert security._looks_like_secret_key(token)
        assert self._bits(security._shannon_entropy(token)) == self._bits(self._oracle(token))


class TestLowercaseRunExceedsStopsAtTheCap:
    """``_lowercase_run_exceeds`` replaced a full-maximum scan with a capped check.

    The caller only compares against a threshold, so the helper answers the
    threshold question directly. These tests pin the boundary in both directions
    -- a run exactly at the cap must NOT trip it, cap+1 must -- so an off-by-one
    in either direction fails.
    """

    @pytest.mark.parametrize(
        ("token", "cap", "expected"),
        [
            ("", 5, False),
            ("ABC123", 5, False),
            ("abcde", 5, False),  # exactly at cap
            ("abcdef", 5, True),  # cap + 1
            ("abcdeX", 5, False),  # run broken before exceeding
            ("abcdeXabcde", 5, False),  # two runs at cap, neither exceeds
            ("Xabcdefghij", 5, True),  # run starts after a non-lower char
            ("abcdefghij", 0, True),  # zero cap: any lowercase exceeds
            ("ABCDEF", 0, False),
            ("aB3" * 20, 5, False),  # never two lowercase in a row
        ],
    )
    def test_boundary(self, token: str, cap: int, expected: bool) -> None:
        assert security._lowercase_run_exceeds(token, cap) is expected

    def test_agrees_with_the_full_maximum_it_replaced(self) -> None:
        def longest_run(token: str) -> int:
            best = current = 0
            for ch in token:
                if ch.islower():
                    current += 1
                    best = max(best, current)
                else:
                    current = 0
            return best

        rng = random.Random(20260811)
        alphabet = string.ascii_letters + string.digits + "+/"
        for _ in range(3000):
            t = "".join(rng.choice(alphabet) for _ in range(rng.randint(0, 44)))
            cap = security._SECRET_MAX_LOWER_RUN
            assert security._lowercase_run_exceeds(t, cap) is (
                longest_run(t) > cap
            ), f"disagreement on {t!r}"


class TestSandboxDeniedCommands:
    """Verify command denial allows/blocks the right ada and AWS patterns.

    Command denial is not injected into the kiro-cli agent spec
    (``config/defaults.json`` does not carry ``deniedCommands``); it is
    enforced solely at KiroCrew's own ``hooks.py`` PreToolUse gate, whose
    decision function is ``security.is_denied`` (built-in regex tier + the
    always-on keystone controls for exfiltration / sensitive-path reads).  These
    tests therefore exercise the real gate directly.
    """

    @staticmethod
    def _is_denied(cmd: str) -> bool:
        from kiro_crew.security import is_denied

        return is_denied(cmd) is not None

    # --- ada: allowed (blocked by kiro-cli at runtime) ---

    def test_ada_update_once_allowed(self) -> None:
        cmd = "ada credentials update --once --account 123 --provider sso --role Admin"
        assert not self._is_denied(cmd)

    def test_ada_update_daemon_allowed(self) -> None:
        cmd = "ada credentials update --account 123 --provider iam --role Admin"
        assert not self._is_denied(cmd)

    def test_ada_profile_add_allowed(self) -> None:
        cmd = "ada profile add --profile staging --account 123 --provider sso --role Y"
        assert not self._is_denied(cmd)

    def test_ada_profile_list_allowed(self) -> None:
        assert not self._is_denied("ada profile list")

    # --- ada: blocked by kiro-cli ---

    # --- AWS CLI: allowed ---

    def test_aws_describe_allowed(self) -> None:
        assert not self._is_denied("aws ec2 describe-instances")

    def test_aws_logs_filter_allowed(self) -> None:
        cmd = "aws logs filter-log-events --log-group-name /aws/lambda/fn"
        assert not self._is_denied(cmd)

    def test_aws_s3_ls_allowed(self) -> None:
        assert not self._is_denied("aws s3 ls s3://my-bucket")

    def test_aws_s3_download_allowed(self) -> None:
        assert not self._is_denied("aws s3 cp s3://bucket/file ./local")

    def test_aws_sts_assume_role_allowed(self) -> None:
        cmd = "aws sts assume-role --role-arn arn:aws:iam::123:role/X"
        assert not self._is_denied(cmd)

    def test_aws_sts_get_caller_identity_allowed(self) -> None:
        assert not self._is_denied("aws sts get-caller-identity")

    # --- AWS CLI: blocked ---

    def test_aws_s3_upload_blocked(self) -> None:
        assert self._is_denied("aws s3 cp ./file s3://bucket/")

    def test_aws_s3_sync_upload_blocked(self) -> None:
        assert self._is_denied("aws s3 sync ./dir s3://bucket/")

    def test_aws_delete_blocked(self) -> None:
        assert self._is_denied("aws ec2 delete-vpc --vpc-id vpc-123")

    def test_aws_terminate_blocked(self) -> None:
        assert self._is_denied("aws ec2 terminate-instances --instance-ids i-1")

    # --- Credential exfiltration: blocked ---

    def test_echo_aws_secret_blocked(self) -> None:
        assert self._is_denied("echo $AWS_SECRET_ACCESS_KEY")

    def test_printenv_aws_blocked(self) -> None:
        assert self._is_denied("printenv AWS_SECRET_ACCESS_KEY")

    def test_env_grep_aws_blocked(self) -> None:
        assert self._is_denied("env | grep AWS_SECRET")

    def test_curl_imds_blocked(self) -> None:
        assert self._is_denied("curl http://169.254.169.254/latest/meta-data/")

    def test_python_boto_creds_blocked(self) -> None:
        cmd = "python3 -c 'import boto3; print(boto3.Session().get_credentials())'"
        assert self._is_denied(cmd)


class TestKiroCliBundledDeniedCommands:
    """Verify the ``self-protection-kill`` built-in rule via the real gate.

    Command denial is not injected into the kiro-cli agent spec — the
    bundled ``config/defaults.json`` does not carry ``deniedCommands``.  The
    self-protection kill guard is now a ``BUILTIN_DENIED_RULES`` entry
    (``self-protection-kill``) enforced at KiroCrew's own ``hooks.py`` PreToolUse
    gate, whose decision function is ``security.is_denied``.  These tests
    therefore exercise ``is_denied`` directly (tool-shape agnostic — the same
    gate runs regardless of whether the tool is ``execute_bash`` or ``shell``).

    Regression tests for the ``kill``/``kirocrew`` pattern false positive,
    narrowed in two steps.

    Step 1 (word boundaries): the original pattern ``.*kill.*kiro.?crew.*``
    matched any command whose argv contained ``~/.kirocrew/skills/...``
    (because ``skills`` contains the substring ``kill``) followed by
    ``kirocrew`` anywhere.  Anchoring the kill word on word boundaries
    stopped skill-dir paths from reading as ``kill``.

    Step 2 (command structure): boundaries still left the rule matching mere
    CO-OCCURRENCE — any command that both called ``kill`` and happened to
    *mention* the product anywhere, in any role (a file being restored, a log
    path, a comment).  The rule is now scoped to the kill TARGET:
    ``pkill``/``killall`` select processes by name, so the product name as an
    argument in the same command segment is the target; bare ``kill`` takes
    PIDs, so it only matches when the name is resolved to one inside a
    command substitution.  ``[^|;&]*`` confines each arm to a single command
    segment, so an unrelated later command in a ``;``/``&&``/pipe chain is not
    captured.  Every by-name kill form is still blocked; ``kiro-crew`` is
    still covered by the ``[-.]?`` separator.
    """

    @staticmethod
    def _is_denied(cmd: str) -> bool:
        from kiro_crew.security import is_denied

        return is_denied(cmd) is not None

    # --- real kill attempts: blocked ---

    def test_pkill_kirocrew_blocked(self) -> None:
        assert self._is_denied("pkill kirocrew")

    def test_kill_kirocrew_pid_blocked(self) -> None:
        assert self._is_denied("kill -9 $(pgrep kirocrew)")

    def test_killall_kirocrew_blocked(self) -> None:
        assert self._is_denied("sudo killall kirocrew")

    def test_kill_kiro_crew_hyphenated_blocked(self) -> None:
        # The `.?` in the pattern covers an optional separator so agents can't
        # bypass with "kiro-crew".
        assert self._is_denied("pkill kiro-crew")

    def test_kill_pidof_substitution_blocked(self) -> None:
        # `pidof` resolves the name to a PID exactly as `pgrep` does, so a
        # resolver-name allowlist would have been a bypass.
        assert self._is_denied("kill $(pidof kirocrew)")

    def test_kill_pidfile_substitution_blocked(self) -> None:
        assert self._is_denied("kill $(cat /var/run/kirocrew.pid)")

    def test_kill_backtick_substitution_blocked(self) -> None:
        assert self._is_denied("kill `pgrep kirocrew`")

    # --- skill-dir false positives: must be allowed ---

    def test_skill_create_sh_kirocrew_domain_allowed(self) -> None:
        """The brazil-workspace skill scaffold must not be blocked."""
        cmd = "/Users/user/.kirocrew/skills/brazil-workspace/create.sh --domain kirocrew"
        assert not self._is_denied(cmd)

    def test_skills_dir_listing_allowed(self) -> None:
        assert not self._is_denied("ls ~/.kirocrew/skills/")

    def test_skill_run_with_kirocrew_arg_allowed(self) -> None:
        cmd = "/Users/user/.kirocrew/skills/coder/run.sh kirocrew --dry-run"
        assert not self._is_denied(cmd)

    def test_bash_skill_script_allowed(self) -> None:
        assert not self._is_denied("bash ~/.kirocrew/skills/something.sh")

    def test_cat_kirocrew_config_allowed(self) -> None:
        # "cat" has no "kill" word anywhere — must not match.
        assert not self._is_denied("cat ~/.kirocrew/config.json")

    # --- incidental-mention false positives: must be allowed ---
    # A bare `kill` takes PIDs, so none of these can aim at a kirocrew process
    # by name; the product name is a FILE, a LOG PATH, or a COMMENT.

    def test_kill_bare_pid_allowed(self) -> None:
        assert not self._is_denied("kill 12345")

    def test_kill_pid_then_restore_config_file_allowed(self) -> None:
        cmd = "kill 12345 && cp /tmp/bk/kirocrew.json ~/.kiro/agents/"
        assert not self._is_denied(cmd)

    def test_kill_pid_then_diff_config_file_allowed(self) -> None:
        cmd = "kill $PID; diff /tmp/bk/kirocrew.json ~/.kiro/agents/kirocrew.json"
        assert not self._is_denied(cmd)

    def test_kill_pid_with_trailing_comment_allowed(self) -> None:
        assert not self._is_denied("kill $PID  # stop the stray kirocrew instance")

    def test_kill_pid_piped_to_kirocrew_log_allowed(self) -> None:
        assert not self._is_denied("kill 12345 | tee /tmp/kirocrew.log")


#: The peers the ssh-to-self floor's own-host seed UDP-``connect``s to learn this
#: machine's primary outbound address per family: RFC 5737 TEST-NET-2 and the
#: RFC 3849 documentation prefix, which no router forwards, so a datagram
#: ``connect`` to them sends no packet. This is what the seed MUST keep pointing
#: at; the stub below records what it pointed at instead of asking the routing
#: table.
_OWN_HOST_PROBE_PEERS = frozenset({("198.51.100.1", 53), ("2001:db8::1", 53)})
#: What the stubbed probe answers as this machine's outbound address, per family:
#: documentation addresses too, distinct from the peers, so a test can tell the
#: seed read the STUB (these turn up in the own-name set) from a real interface.
_STUB_OWN_ADDRESS: dict[int, str] = {
    socket.AF_INET: "203.0.113.7",
    socket.AF_INET6: "2001:db8::7",
}


class _InertDatagramSocket:
    """A datagram socket that connects nothing.

    ``connect`` records the peer instead of asking the routing table for a
    source address; ``getsockname`` answers the documentation address for the
    family; ``fileno`` refuses so the per-interface ioctl sweep, which needs a
    real descriptor, contributes nothing (its own ``except`` swallows this).
    """

    def __init__(self, family: int, recorded: list[tuple[int, object]]) -> None:
        self._family = family
        self._recorded = recorded

    def __enter__(self) -> _InertDatagramSocket:
        return self

    def __exit__(self, *exc: object) -> None:
        return None

    def connect(self, peer: object) -> None:
        self._recorded.append((self._family, peer))

    def getsockname(self) -> tuple[str, int]:
        return (_STUB_OWN_ADDRESS.get(self._family, ""), 0)

    def fileno(self) -> int:
        raise OSError("inert datagram socket has no descriptor")

    def close(self) -> None:
        return None


class TestBuiltinDenyPatterns:
    """Tests for is_denied() from security.py BUILTIN_DENY_PATTERNS.

    Credential-related patterns were removed — the OS-level sandbox
    (sandbox.py) hides credential files and deniedCommands in the
    kiro-cli agent config blocks bash-level exfiltration.  Only
    explicit secret-fetching tool names and destructive ops remain.
    """

    @pytest.fixture(autouse=True)
    def _own_host_seed_connects_nothing(self, monkeypatch) -> list[tuple[int, object]]:
        """The ``ssh`` cases here are the first own-host lookup in the process.

        ``is_denied("ssh ...")`` seeds the ssh-to-self floor's own-host set on
        first use and, once the backoff allows, starts a DNS enrichment thread.
        The seed learns this machine's outbound address with a UDP ``connect``
        to a documentation peer -- packet-less, but a real socket the routing
        table has to answer -- and the worker resolves real names. These tests
        are about the deny patterns, not about this host's identity, so the
        datagram socket is stubbed at the seam production reads -- the module's
        ``socket`` binding, datagram construction only; every other socket kind
        passes through -- and the enrichment backoff is pushed past the test.
        The seed still RUNS, through the stub, so the peers it names are
        observable (``_OWN_HOST_PROBE_PEERS``) and the address it reads back is
        the stub's. The enumeration's other layers -- the per-interface ioctl
        sweep (its ``fileno`` is refused), ``/proc/net/if_inet6`` and the
        Windows / macOS adapter tables -- are local reads that may still yield
        this host's real addresses, so the enumeration's result is filtered to
        the stub's addresses before it enters the own-name set: what the deny
        patterns see is host-independent, and the filter admitting the stub's
        addresses is what proves the seed read the stub.

        The own-host cache is reset for the test and restored after it, so the
        stub's addresses never become another test's idea of this machine.
        """
        from kiro_crew.security import argv_floor

        recorded: list[tuple[int, object]] = []
        real_socket = argv_floor.socket
        real_interface_addresses = argv_floor._own_interface_addresses
        stub_addresses = set(_STUB_OWN_ADDRESS.values())

        def _stub_addresses_only() -> set[str]:
            return real_interface_addresses() & stub_addresses

        class _SocketModule:
            """``socket`` with datagram construction routed to the inert stub."""

            def __getattr__(self, name: str):
                return getattr(real_socket, name)

            def socket(self, family: int = -1, type: int = -1, proto: int = -1, fileno=None):
                if type == real_socket.SOCK_DGRAM:
                    return _InertDatagramSocket(family, recorded)
                return real_socket.socket(family, type, proto, fileno)

        monkeypatch.setattr(argv_floor, "socket", _SocketModule())
        monkeypatch.setattr(argv_floor, "_own_interface_addresses", _stub_addresses_only)
        monkeypatch.setattr(argv_floor, "_OWN_HOST_NAMES_CACHE", None)
        monkeypatch.setattr(argv_floor, "_OWN_HOST_RESOLVE_DONE", False)
        monkeypatch.setattr(argv_floor, "_OWN_HOST_RESOLVE_NEXT_TRY", float("inf"))
        return recorded

    def test_allows_command_with_credential_in_path(self) -> None:
        """Commands in dirs like CredentialValidatorServiceCDK must not be blocked."""
        from kiro_crew.security import is_denied

        cmd = "cd /home/user/src/CredentialValidatorServiceCDK && git status"
        assert is_denied(cmd) is None

    def test_allows_credential_in_package_name(self) -> None:
        """Package names containing 'credential' must not be blocked."""
        from kiro_crew.security import is_denied

        assert is_denied("ada credentials update --account 123") is None
        assert is_denied("credential-rotation-service build") is None
        assert is_denied("get-credentials --profile default") is None

    def test_blocks_secretsmanager_destructive(self) -> None:
        """The new catalog blocks the REAL destructive Secrets Manager CLI verb.

        The old glob catalog blocked bare tool-name tokens like
        ``get_secret_value`` / ``read_secret_store`` — underscore/no-prefix
        method names the AWS CLI never emits.  The new ``credential-exfil`` /
        ``aws-destructive`` rules match the real hyphenated CLI instead; a plain
        secret READ is intentionally allowed (reading is not exfiltration — the
        always-on keystone catches actual exfil), while a destructive
        ``delete-secret`` stays blocked.
        """
        from kiro_crew.security import is_denied

        assert is_denied("aws secretsmanager delete-secret --secret-id x") is not None

    def test_secret_exfil_still_blocked_by_keystone(self) -> None:
        """Dumping an AWS secret env var stays blocked (credential-exfil rule)."""
        from kiro_crew.security import is_denied

        assert is_denied("echo $AWS_SECRET_ACCESS_KEY") is not None

    def test_blocks_git_push(self) -> None:
        from kiro_crew.security import is_denied

        # ── Real publish invocations: must remain BLOCKED ──
        assert is_denied("git push origin main") is not None
        assert is_denied("git push origin main --force") is not None
        assert is_denied("git -C /Volumes/Foo/Bar push") is not None
        assert is_denied("git -C /Volumes/Foo/Bar push --force") is not None
        assert is_denied("git_push") is not None
        assert is_denied("git_push origin main") is not None
        # ── Legitimate stash invocations: must be ALLOWED ──
        assert is_denied("git stash push") is None
        assert is_denied("git stash push -m 'wip'") is None
        assert is_denied("git -C /path stash push") is None
        assert is_denied("git -c core.autocrlf=true stash push -m 'wip'") is None
        # ── Path containing "stash" must NOT bypass deny ──
        # The exception pattern requires a literal " stash push" with a leading
        # space, so "/tmp/stash push" (slash, not space) doesn't match.
        assert is_denied("git -C /tmp/stash push origin main --force") is not None
        # ── Chaining-bypass attempts must remain BLOCKED ──
        # Per-segment evaluation: the embedded real publish lives in its own
        # segment after splitting on `;` / `&&` / `$(` / backtick, so it
        # matches the deny pattern even though an outer stash segment exists.
        assert is_denied("git stash push; git push origin main --force") is not None
        assert is_denied("git stash push && git push origin main") is not None
        assert is_denied('git stash push -m "$(git push origin main --force)"') is not None
        assert is_denied("git stash push -m `git push origin main`") is not None
        # Newline-chained publish (heredoc / multi-statement script body).
        assert is_denied("echo starting\ngit push origin main") is not None
        # Leading whitespace before the publish must not evade.
        assert is_denied("   git push origin main") is not None
        # Bare ``git push`` (no remote/branch — pushes current branch to the
        # default remote) inside a subshell / backtick, where ``push`` is
        # followed by a closing metacharacter rather than whitespace/EOL.
        # A naive ``push(?:\s|$)`` terminator missed these.
        assert is_denied("echo $(git push)") is not None
        assert is_denied("result=`git push`") is not None
        assert is_denied("x=$(git push); echo done") is not None
        assert is_denied("git push|cat") is not None
        assert is_denied("git push&") is not None

    def test_allows_legitimate_stash_in_pipeline(self) -> None:
        """Per-segment evaluation: legitimate ``git stash push`` followed by
        unrelated commands via shell separators is now allowed.

        Under the prior whole-string design these were
        over-blocked because any separator suppressed the stash exception.
        Per-segment evaluation classifies each segment independently — the
        stash segment matches its exception, the trailing segments don't
        match any deny pattern, so the whole input is allowed.

        The chaining-bypass protection is preserved: see
        ``test_blocks_git_push`` for the bypass-attempt cases that remain
        blocked because the embedded segment IS a real publish.
        """
        from kiro_crew.security import is_denied

        # The original pain point: stash output piped into a filter.
        assert is_denied('git stash push -m "wip" 2>&1 | tail -3') is None
        # Stash followed by status / log via &&.
        assert is_denied("git stash push && git status") is None
        assert is_denied("git stash push && git log --oneline -5") is None
        # Stash piped through grep / head.
        assert is_denied("git stash push -u | head") is None
        assert is_denied('git stash push -m "wip" | grep saved') is None
        # Stash followed by an unrelated git operation.
        assert is_denied("git stash push && git checkout main") is None
        assert is_denied("git stash push; git rebase origin/main") is None

    def test_blocks_command_substitution_boundary_evasion(self) -> None:
        """Pass-1 whole-string deny closes the segment-boundary evasion vector.

        ``git$(echo ' ')push origin main`` evaluates to ``git push origin
        main`` in bash. A naive pass-2-only implementation would split on
        ``$(`` and ``)`` producing ``["git", "echo ' '", "push origin main"]``
        — no segment contains both substrings, so the deny pattern would
        not match and the publish would slip through.

        With pass-1 whole-string deny, the input is checked against the
        glob first. ``*git*push*`` matches the full string (it contains
        both substrings), and the ``* stash push*`` exception requires a
        literal ` stash push` substring (with leading space) which this
        input lacks → outright deny on pass 1, no fall-through to pass 2.
        """
        from kiro_crew.security import is_denied

        # Concrete bypass attempt — flagged by review-bot on rev 1.
        assert is_denied("git$(echo ' ')push origin main") is not None
        # Other variants that exploit the same boundary trick.
        assert is_denied("git$(echo)push origin") is not None
        assert is_denied("git`echo`push origin main") is not None
        assert is_denied("git$()push origin") is not None

    def test_blocks_background_operator_bypass(self) -> None:
        """``&`` (single ampersand, the bash background operator) must split
        segments like ``;`` and ``&&``.

        Guards a review-bot finding on rev 2: the rev-2
        ``_CMD_SPLIT_RE`` covered ``&&`` but not a lone ``&``, so
        ``git stash push & git push origin main`` (which bash backgrounds
        the left command and immediately runs the right) stayed a single
        segment that matched both the deny pattern and the stash exception
        → falsely allowed.

        The fix uses ``&(?!&)`` after ``&&`` in the alternation so ``&&``
        is consumed as a single token and a lone ``&`` is split on.
        """
        from kiro_crew.security import is_denied

        # Core bypass.
        assert is_denied("git stash push & git push origin main") is not None
        assert is_denied("git stash push -m 'wip' & git push --force") is not None
        # Trailing ``&`` to background a real publish.
        assert is_denied("git push origin main &") is not None
        # ``&&`` must continue to work — it's a different operator entirely
        # and was already covered.
        assert is_denied("git stash push && git push origin main") is not None
        # Legitimate stash backgrounded with no embedded publish should
        # still be ALLOWED — the second segment must be deny-free.
        assert is_denied("git stash push -m 'wip' & echo done") is None

    def test_two_pass_evaluates_all_deny_patterns(self, monkeypatch) -> None:
        """Pass 1 must continue iterating deny patterns after granting an
        exception, so a *different* pattern with no exception still triggers
        an outright deny.

        Guards a review-bot finding on rev 1: the original
        pass-2 inner loop used ``break`` after granting an exception, which
        would skip remaining patterns.  In rev 2 the equivalent logic in
        pass 1 records the exception-matched pattern as a candidate and
        keeps iterating (this test exercises that path); pass 2 uses
        ``continue`` for the same reason (covered by other tests).

        ``_DENY_EXCEPTIONS`` ships only the search-verb carve-out on the two
        ``local-destructive`` rm rules, so the multi-pattern interaction still cannot
        be expressed with live catalog data (one input would have to trip two rm rules
        at once).  We install a synthetic two-glob scenario to
        keep exercising the loop-control invariant directly: the input matches
        an exception-carrying glob AND a second glob with no exception, so pass 1
        must fall through to the second glob and deny outright.  A ``break``
        regression would skip the second glob and falsely allow.
        """
        import kiro_crew.security as security_module

        monkeypatch.setattr(security_module, "_DENY_EXCEPTIONS", {"*alpha*": ["* stash *"]})
        # Pass 1 sees:
        #   *alpha* — matches, " stash " whole-string exception matches → candidate
        #   *bravo* — matches, no exception → outright deny
        assert (
            security_module.is_denied("alpha stash bravo", extra_patterns=["*alpha*", "*bravo*"])
            is not None
        )
        # Confidence check: with only the exception-carrying glob and no second
        # deny, the command is allowed (the candidate path itself does not deny).
        assert security_module.is_denied("alpha stash here", extra_patterns=["*alpha*"]) is None

    def test_allows_commit_message_mentioning_push(self) -> None:
        """A ``git commit`` whose message merely mentions ``push`` must be
        ALLOWED — ``push`` is not the git verb here.

        Guards the silent ``Tool use aborted`` on the Claude Code
        provider (interest thread p1780505710223359): the broad
        ``*git*push*`` substring glob matched any commit whose ``-m`` body
        contained the word ``push``, so the host gate denied it and
        the claude-agent-acp adapter surfaced the cryptic abort with no
        approval prompt.  Anchoring ``push`` as the git subcommand fixes it
        while keeping real ``git push`` blocked.
        """
        from kiro_crew.security import is_denied

        assert is_denied("git commit -m 'fix: do not push secrets to remote'") is None
        assert (
            is_denied("git commit -m 'refactor: push results downstream and reset cache'") is None
        )
        # Multi-line / heredoc-style body mentioning push.
        assert is_denied("git commit -m 'docs: explain when to push and when to rebase'") is None

    # ── a destructive literal handed to a read-only search verb ──
    # Assembled at runtime so this test module is not itself an un-greppable
    # needle: a plain literal here would make the file impossible to search for
    # by the very rule it exercises, which is the bug being fixed.
    ROOT_WIPE = "rm -" + "rf /"
    HOME_WIPE = "rm -" + "rf ~"

    def test_allows_a_destructive_literal_as_a_search_operand(self) -> None:
        """A read-only search verb cannot execute its operands, so a destructive
        string handed to it as a PATTERN is text and must be ALLOWED.

        ``local-destructive-rm-rf-root`` / ``-home`` are
        plain literal patterns matched over the segment text, so grepping FOR
        the rule's own subject matter was refused exactly as if the deletion had
        been typed — which prevented nothing (the same work completes by moving
        the payload into a file, which is not scanned) while blocking anyone
        working ON these rules.
        """
        from kiro_crew.security import is_denied

        for verb in ("grep -rn", "egrep -r", "fgrep"):
            assert is_denied(f'{verb} "{self.ROOT_WIPE}" test/') is None, verb
            assert is_denied(f'{verb} "{self.HOME_WIPE}" test/') is None, verb

    def test_a_search_pattern_containing_an_alternation_is_still_denied(self) -> None:
        """KNOWN LIMITATION, pinned deliberately.

        The command that motivated the report puts a regex ALTERNATION in the
        search pattern::

            grep -rln "rm-rf-root\\|rm -rf /" test/

        ``_CMD_SPLIT_RE`` is quote-unaware, so the ``|`` inside the quoted
        pattern is read as a pipe and the command splits into
        ``grep -rln "rm-rf-root\\`` and ``rm -rf /" test/``.  The second segment
        genuinely looks like a bare deletion in command position, so the
        verb-anchored carve-out cannot reach it — the exception is keyed to
        segments that START with a search verb, and by design it must stay that
        way or ``grep x | xargs <destructive>`` would be exonerated too.

        Closing this case needs quote-aware SEGMENTATION, which is a separate and
        much larger change (it also has to stay compatible with the
        quote-NORMALIZED matching added for evasion resistance).  Asserting the
        current behaviour rather than xfailing it, so the boundary is explicit and
        a future segmentation fix has to update this test consciously.
        """
        from kiro_crew.security import is_denied

        assert is_denied(f'grep -rln "rm-rf-root\\|{self.ROOT_WIPE}" test/') is not None
        # The same search without the alternation IS exonerated — isolating the
        # cause to segmentation rather than to the carve-out.
        assert is_denied(f'grep -rln "{self.ROOT_WIPE}" test/') is None

    def test_still_denies_the_real_destruction_and_any_chaining(self) -> None:
        """The carve-out is anchored at the search verb, so it must not exonerate
        a destructive command — including one chained after a real search.

        This is the half that makes the carve-out safe: ``_CMD_SPLIT_RE`` splits on
        every execution boundary, so the destructive SEGMENT is still evaluated in
        its own right and the Pass 1 whole-string exception only defers to Pass 2.
        """
        from kiro_crew.security import is_denied

        # Bare, and behind a wrapper that DOES execute its operands.
        assert is_denied(self.ROOT_WIPE) is not None
        assert is_denied(self.HOME_WIPE) is not None
        assert is_denied(f"sudo {self.ROOT_WIPE}") is not None
        assert is_denied(f"grep -rl x test/ | xargs {self.ROOT_WIPE}") is not None
        # Chained after a genuine search, across every separator the splitter knows.
        for joiner in ("&&", ";", "||", "|", "&", "\n"):
            cmd = f'grep -rn "needle" test/ {joiner} {self.ROOT_WIPE}'
            assert is_denied(cmd) is not None, joiner
        # Command substitution, both spellings.
        assert is_denied(f'grep -rn "$({self.ROOT_WIPE})" test/') is not None
        assert is_denied(f'grep -rn "`{self.ROOT_WIPE}`" test/') is not None

    def test_the_carve_out_does_not_exonerate_other_rules(self) -> None:
        """The exception is keyed to the two rm patterns only, so a search verb
        must not become a blanket allowlist for unrelated deny rules."""
        from kiro_crew.security import is_denied

        # A different local-destructive rule in the same segment as a search verb.
        assert is_denied("grep -rn x test/ && mkfs.ext4 /dev/sda1") is not None

    def test_a_search_verb_fragment_inside_an_operand_does_not_exonerate(self) -> None:
        """A ``/grep `` fragment ANYWHERE in a destructive command must not exonerate it.

        Guards the first bypass found reviewing the carve-out fix. An
        earlier revision also carried path-qualified globs (``*/grep *``) so that
        ``/usr/bin/grep ...`` would be exonerated too. ``fnmatch`` is a full
        match, but ``*`` crosses spaces, so a LEADING ``*`` is really an
        unanchored substring test: ``*/grep *`` matches
        ``rm -rf / /bin/grep x`` -- a genuine root wipe that merely lists a path
        containing ``/grep `` among its operands -- and the deletion was ALLOWED.

        Only the bare ``<verb> *`` form is safe, because it forces the segment to
        BEGIN with the verb. The cost is that a path-qualified search is no
        longer exonerated, asserted below so the trade-off is explicit rather
        than looking like an oversight.
        """
        from kiro_crew.security import is_denied

        assert is_denied(f"{self.ROOT_WIPE} /bin/grep x") is not None
        assert is_denied(f"{self.ROOT_WIPE} x/grep y") is not None
        assert is_denied(f"{self.HOME_WIPE} /usr/bin/grep z") is not None
        # The accepted trade-off: a path-qualified search verb is NOT exonerated,
        # because no glob can express "the first token's basename is the verb".
        assert is_denied(f'/usr/bin/grep -rn "{self.ROOT_WIPE}" test/') is not None

    def test_no_shell_active_construct_is_ever_exonerated(self) -> None:
        """A command hidden in any expansion behind a search verb must stay denied.

        Guards the second and fourth bypasses found reviewing the carve-out's own
        fix. ``_CMD_SPLIT_RE`` isolates ``;`` ``|`` ``&&`` ``&`` ``$(`` ``)``
        backtick and newline, but NOT ``<(`` / ``>(`` / ``${`` / a bare ``(``. So
        ``_split_segments`` cuts ``grep x <(<destructive>)`` only at the trailing
        ``)``, and ``grep x ${ <destructive>;}`` only at the ``;`` -- in both
        cases leaving the destructive command glued to the search verb instead of
        isolated in its own command position, while bash still executes it.

        The first attempt blocklisted just ``(`` and was defeated by the bash 5.3
        funsub. ``_exception_eligible`` now refuses any view containing a
        shell-active character, closing the class instead of chasing spellings.
        """
        from kiro_crew.security import is_denied

        # Process substitution, input and output forms, and a bare subshell.
        assert is_denied(f"grep x <({self.ROOT_WIPE}tmp/victim)") is not None
        assert is_denied(f'grep -rn "x" <({self.ROOT_WIPE})') is not None
        assert is_denied(f"grep x >({self.ROOT_WIPE}tmp/victim)") is not None
        assert is_denied(f"grep x ({self.ROOT_WIPE})") is not None
        # bash >= 5.3 funsub -- the opener that defeated the `(`-only guard.
        assert is_denied(f"grep x ${{ {self.ROOT_WIPE};}}") is not None
        assert is_denied(f"grep x ${{ {self.HOME_WIPE};}}") is not None
        # Command substitution and backticks (already split, asserted anyway).
        assert is_denied(f'grep -rn "$({self.ROOT_WIPE})" test/') is not None
        assert is_denied(f'grep -rn "`{self.ROOT_WIPE}`" test/') is not None
        # Confidence check: the plain search is still exonerated, so the guard
        # narrowed exactly the shell-active forms and nothing else.
        assert is_denied(f'grep -rn "{self.ROOT_WIPE}" test/') is None

    def test_a_search_verb_that_can_execute_a_helper_is_not_exonerated(self) -> None:
        """Only verbs with no exec flag are exonerated.

        Guards the third bypass found reviewing the carve-out fix. The
        carve-out's premise is that the verb cannot execute its operands, and
        that is a property of the specific tool, not of "being a search tool":
        ``rg --pre <cmd>`` runs a preprocessor and ``ack --pager <cmd>`` runs a
        pager, so ``rg --pre sh "<destructive>" payload.sh`` really does execute.

        ``rg`` and ``ack`` were therefore dropped from the allowlist, which makes
        the premise true rather than merely asserted. ``grep``/``egrep``/``fgrep``
        have no flag that spawns a helper.
        """
        from kiro_crew.security import is_denied

        assert is_denied(f'rg --pre sh "{self.ROOT_WIPE}tmp/victim" payload.sh') is not None
        # Dropped wholesale, not just for the executing flag: a glob cannot tell
        # `rg PATTERN` from `rg --pre sh PATTERN`, so the verb cannot be trusted.
        assert is_denied(f'rg "{self.ROOT_WIPE}" src/') is not None
        assert is_denied(f'ack "{self.ROOT_WIPE}" src/') is not None

    def test_a_pipeline_into_an_interpreter_is_never_exonerated(self) -> None:
        """A search piped into something that executes what it emitted must deny.

        Guards the fifth bypass found reviewing the carve-out fix.
        ``grep '<destructive>' payload.py | python`` splits at the pipe, so the
        Pass 2 grep segment looks innocent on its own and the bare ``python``
        segment matches no rule -- the pipeline as a whole was allowed, and the
        interpreter runs the line the search emitted.

        Note the pipe cannot be caught in the Pass 2 segment (the splitter has
        already consumed it). What closes this is refusing the separators in the
        PASS 1 whole-string view, so the whole-string deny match stands instead
        of deferring to the innocent-looking segment. Hence
        ``_exception_eligible`` requires a single plain command, not merely one
        free of expansion openers.
        """
        from kiro_crew.security import is_denied

        assert is_denied(f"grep '{self.ROOT_WIPE}tmp/victim' payload.py | python") is not None
        assert is_denied(f"grep '{self.ROOT_WIPE}' payload.sh | sh") is not None
        assert is_denied(f"grep '{self.ROOT_WIPE}' f | bash -s") is not None
        # A compound whose later stage is inert is denied for the same reason:
        # an exception must not speak for more than one command.
        assert is_denied(f"grep '{self.ROOT_WIPE}' f && echo done") is not None
        # Confidence check: the single plain search remains exonerated.
        assert is_denied(f'grep -rn "{self.ROOT_WIPE}" test/') is None

    def test_feature_push_not_blocked_by_prose_push_word_in_earlier_segment(self) -> None:
        """A legit feature-branch push must be ALLOWED even when an EARLIER
        chained segment merely contains the word ``push``.

        Ported upstream regression guard (from the upstream project):
        upstream's two-pass gate matched a bare ``\\bpush\\b`` in any segment,
        so prose like ``git commit -m 'ready to push'`` was denied before the
        refspec normalizer could allow the real feature-branch push. This
        fork's ``_is_push_to_protected_branch`` never had that pass — it gates
        each segment on ``_is_git_publish`` and parses via the verb-anchored
        ``_git_push_args`` — but this test locks in the contract: a prose
        "push" in an earlier chained segment never blocks a real
        feature-branch push, while chained protected pushes stay denied.
        """
        from kiro_crew.security import is_denied

        assert is_denied("git commit -m 'ready to push' && git push origin feature-x") is None
        assert is_denied("echo 'time to push' && git push origin my-feature") is None
        # The protective behavior must remain: a real protected push chained
        # AFTER a benign feature push is still blocked.
        assert is_denied("git push origin feat && git push origin main") is not None
        assert is_denied("git commit -m 'ready to push' && git push origin main") is not None

    def test_allows_git_verbs_with_push_substring_args(self) -> None:
        """Other git subcommands whose arguments contain ``push`` (branch
        names, grep patterns, config keys) must be ALLOWED — only an actual
        ``git push`` invocation is a publish.
        """
        from kiro_crew.security import is_denied

        assert is_denied("git log --grep push") is None
        assert is_denied("git config push.default current") is None
        assert is_denied("git branch --contains pushed-feature") is None
        assert (
            is_denied("git switch -c fix/security-tighten-git-push origin/beta-braveheart") is None
        )
        # ``git remote`` referencing a remote literally named "push".
        assert is_denied("git remote show push") is None

    def test_allows_ssh_remote_command_without_publish(
        self, _own_host_seed_connects_nothing: list[tuple[int, object]]
    ) -> None:
        """A plain ``ssh host '<cmd>'`` whose remote command contains the word
        ``push`` (but is not a real ``git push``) must be ALLOWED.

        Covers the ssh symptom from the same thread: remote
        interactions starting with ``ssh xxxx`` were aborting.

        The first ``ssh`` verdict in a process also seeds the own-host set. That
        seed runs here through the inert datagram stub: the peers it names are
        the documentation addresses (the seam kept pointing where it must), and
        the own addresses that reached the own-name set are the STUB's: they
        got there only because the real enumeration read them back from the
        stubbed socket, and the fixture's filter admits nothing else.
        """
        from kiro_crew.security import argv_floor, is_denied

        assert is_denied("ssh dev-dsk 'cd /workplace && git status'") is None
        assert is_denied("ssh dev-dsk 'git commit -m \"address push-back from review\"'") is None
        recorded = _own_host_seed_connects_nothing
        assert {peer for _family, peer in recorded} == _OWN_HOST_PROBE_PEERS, recorded
        assert {family for family, _peer in recorded} == {socket.AF_INET, socket.AF_INET6}
        assert argv_floor._OWN_HOST_NAMES_CACHE is not None
        assert set(_STUB_OWN_ADDRESS.values()) <= argv_floor._OWN_HOST_NAMES_CACHE

    def test_blocks_ssh_remote_real_git_push(self) -> None:
        """A real ``git push`` inside an ``ssh`` remote command stays BLOCKED."""
        from kiro_crew.security import is_denied

        assert is_denied("ssh host 'cd /repo && git push origin main'") is not None

    def test_deny_event_audit_emitted_on_block(self, monkeypatch) -> None:
        """Every denial path emits a ``deny_event`` SEL event.

        Regression test for review-bot finding on rev 1: prior
        revision only emitted SEL audit on the exception-granted path,
        leaving denials un-audited.
        """
        import kiro_crew.security as security_module

        captured: list[tuple[str, str, str]] = []

        def fake_emit(tool_name: str, deny_pattern: str, segment: str) -> None:
            captured.append((tool_name, deny_pattern, segment))

        monkeypatch.setattr(security_module, "_emit_deny_event", fake_emit)
        # Git-publish deny. The audited pattern is now the RULE's own pattern, not
        # the human "git push" label — a floor denial has to map back to a rule id
        # in the SEL trail, the way every other deny does.
        result = security_module.is_denied("git push origin main --force")
        assert result is not None
        assert len(captured) == 1
        assert captured[0][0] == "git push origin main --force"
        assert (
            captured[0][1]
            == security_module._GIT_PUBLISH_FLOOR_BY_ID["git-publish-push-protected-branch-name"]
        )
        # Chained bypass attempt is caught on the whole string (the separator
        # is part of the git-publish anchor), and still audited.
        captured.clear()
        result = security_module.is_denied("git stash push && git push origin main")
        assert result is not None
        assert any("git push origin main" in c[2] for c in captured)
        # A regex-tier built-in deny (real hyphenated AWS CLI) records the
        # matched rule pattern verbatim.
        captured.clear()
        result = security_module.is_denied("aws ec2 terminate-instances --instance-ids i-1")
        assert result is not None
        assert captured[0][1] == (
            r"aws(?:\s+--?[a-z-]+(?:[= ]\S+)?)*\s+ec2"
            r"(?:\s+--?[a-z-]+(?:[= ]\S+)?)*\s+terminate-instances.*"
        )

    def test_blocks_delete_stack(self) -> None:
        """The real hyphenated CloudFormation teardown is blocked.

        The old glob catalog matched the underscore token ``delete_stack`` the
        AWS CLI never emits; the new catalog matches the real
        ``aws cloudformation delete-stack`` invocation instead (see
        ``test_blocks_real_hyphenated_destructive_aws_cli``).
        """
        from kiro_crew.security import is_denied

        assert is_denied("aws cloudformation delete-stack --stack-name foo") is not None

    def test_blocks_terminate_instance(self) -> None:
        """The real hyphenated EC2 terminate is blocked (underscore form retired)."""
        from kiro_crew.security import is_denied

        assert is_denied("aws ec2 terminate-instances --instance-ids i-123") is not None

    def test_blocks_real_hyphenated_destructive_aws_cli(self) -> None:
        """Real AWS CLI destructive subcommands use HYPHENS, not underscores.

        The built-in deny globs only match the underscore
        forms (``*delete_stack*`` …), which the AWS CLI never emits — so the
        actual destructive invocations (``aws cloudformation delete-stack``
        …) slipped through ``is_denied`` entirely. ``mcp_cron._vet_shell_command``
        relies on ``is_denied`` to stop a prompt-injected ``cron_add`` from
        scheduling destructive shell, so this was an exploitable gap on the
        cron command path.
        """
        from kiro_crew.security import is_denied

        assert is_denied("aws cloudformation delete-stack --stack-name prod") is not None
        assert is_denied("aws ec2 terminate-instances --instance-ids i-123") is not None
        assert is_denied("aws s3api delete-bucket --bucket prod-data") is not None
        assert is_denied("aws dynamodb delete-table --table-name prod") is not None
        # NB: the underscore/boto3 method-name forms (``terminate_instances``,
        # ``delete_table``) are intentionally NOT blocked by the new catalog —
        # it ports only the real hyphenated AWS CLI regexes (the CLI never emits
        # the underscore forms).  See ``test_blocks_terminate_instance``.

    def test_allows_benign_aws_reads_after_deny_fix(self) -> None:
        """The hyphenated destructive patterns must not over-block benign
        AWS reads or package/command names that merely contain 'delete'/'credential'."""
        from kiro_crew.security import is_denied

        # Read-only AWS operations stay allowed.
        assert is_denied("aws ec2 describe-instances") is None
        assert is_denied("aws s3 ls s3://my-bucket") is None
        assert is_denied("aws sts get-caller-identity") is None
        assert is_denied("aws logs filter-log-events --log-group-name /x") is None
        # Non-destructive verbs that merely contain a destructive word as a
        # substring of a DIFFERENT token must not trip the specific globs.
        assert is_denied("credential-rotation-service build") is None
        assert is_denied("get-credentials --profile default") is None

    def test_allows_git_status(self) -> None:
        from kiro_crew.security import is_denied

        assert is_denied("git status") is None

    def test_allows_git_log(self) -> None:
        from kiro_crew.security import is_denied

        assert is_denied("git -P log --oneline -5") is None

    def test_allows_cr_command(self) -> None:
        from kiro_crew.security import is_denied

        assert is_denied("cr --summary 'Fix test discovery'") is None


class TestOAuthAuthorizationUrlRedaction:
    """OAuth entropy is exempt only in the dedicated ACP banner-safety path."""

    STATE = "opaque-state-123"
    CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    BARE_AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    BARE_AWS_SECRET_ALNUM = "wJalrXUtnFEMIxK7MDENGybPxRfiCYEXAMPLEKEY"
    GITHUB_TOKEN = "ghp_" "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"
    NOTION_URL = (
        "https://api.notion.com/v1/oauth/authorize"
        "?client_id=client123&response_type=code"
        f"&state={STATE}&code_challenge={CHALLENGE}"
        "&code_challenge_method=S256"
    )

    @staticmethod
    def _assert_general_redactors_remove_secret(url: str, secret: str) -> None:
        text = f"Model output: {url}"
        for redactor in (redact_credentials, redact_exfiltration_urls):
            cleaned, warnings = redactor(text)
            assert secret not in cleaned
            assert warnings

    def test_exact_notion_authorize_url_passes_banner_only(self) -> None:
        assert len(self.CHALLENGE) == 43
        assert oauth_url_contains_credential(self.NOTION_URL) is False

        # The generic URL redactor handles arbitrary model/agent text and does
        # not inherit the banner-only OAuth entropy carve-out.
        cleaned, warnings = redact_exfiltration_urls(self.NOTION_URL)
        assert cleaned != self.NOTION_URL
        assert warnings

    def test_diagnostic_identifies_long_query_parameter_shape(self) -> None:
        opaque_state = "Ab9_" * 64
        url = "https://id.example-idp.com/authorize?state=" + opaque_state

        diagnostic = security.diagnose_oauth_url_credential(url)

        assert diagnostic is not None
        assert diagnostic.rule == "exfil_query_length"
        assert diagnostic.component == "query_parameter"
        assert diagnostic.parameter == "state"
        assert diagnostic.shape.length == len(opaque_state)
        assert diagnostic.shape.ascii_uppercase == 64
        assert diagnostic.shape.ascii_lowercase == 64
        assert diagnostic.shape.digits == 64
        assert diagnostic.shape.symbols == 64

    def test_diagnostic_identifies_nonstandard_param_bare_secret_rule(self) -> None:
        url = self.NOTION_URL + f"&session_blob={self.BARE_AWS_SECRET_ALNUM}"

        diagnostic = security.diagnose_oauth_url_credential(url)

        assert diagnostic is not None
        assert diagnostic.rule == "credential_scan_bare_secret_raw"
        assert diagnostic.component == "query_parameter"
        assert diagnostic.parameter is None
        assert diagnostic.shape.length == len(self.BARE_AWS_SECRET_ALNUM)

    @pytest.mark.parametrize("parameter", ["state", "code_challenge"])
    def test_recognized_oauth_entropy_does_not_hit_bare_secret_lottery(
        self, parameter: str
    ) -> None:
        digest = hashlib.sha256(b"synthetic-oauth-entropy-regression").digest()
        if parameter == "state":
            entropy = base64.b64encode(digest).decode()[:40]
            url = self.NOTION_URL.replace(self.STATE, entropy, 1)
        else:
            entropy = base64.urlsafe_b64encode(digest).decode().rstrip("=")
            url = self.NOTION_URL.replace(self.CHALLENGE, entropy, 1)

        # The fixed digest is deliberately one whose shape reaches the generic
        # bare-secret heuristic. OAuth entropy at an approved endpoint must not
        # inherit that probabilistic verdict.
        assert security._text_contains_bare_secret(entropy)
        assert security.diagnose_oauth_url_credential(url) is None
        assert oauth_url_contains_credential(url) is False

    @pytest.mark.parametrize("parameter", ["redirect_uri", "client_id"])
    def test_non_entropy_oauth_parameter_keeps_markerless_secret_scan(self, parameter: str) -> None:
        secret = self.BARE_AWS_SECRET_ALNUM
        url = self.NOTION_URL + f"&{parameter}={secret}"

        assert len(secret) == 40
        assert security._text_contains_bare_secret(secret)
        assert oauth_url_contains_credential(url) is True

    def test_entropy_exemption_does_not_cover_adversarial_url_shapes(self) -> None:
        digest = hashlib.sha256(b"synthetic-oauth-entropy-regression").digest()
        entropy = base64.b64encode(digest).decode()[:40]
        approved = self.NOTION_URL.replace(self.STATE, entropy, 1)
        adversarial_urls = {
            "http": approved.replace("https://", "http://", 1),
            "explicit-port": approved.replace("api.notion.com", "api.notion.com:443", 1),
            "host-suffix": approved.replace("api.notion.com", "api.notion.com.attacker.example", 1),
            "path-suffix": approved.replace("/v1/oauth/authorize", "/v1/oauth/authorize/extra", 1),
            "userinfo": self.NOTION_URL.replace("https://", f"https://{entropy}@", 1),
            "path": self.NOTION_URL.replace(
                "/v1/oauth/authorize", f"/v1/oauth/{entropy}/authorize", 1
            ),
            "path-params": self.NOTION_URL.replace(
                "/v1/oauth/authorize", "/v1/oauth/authorize;session=ok", 1
            ),
            "fragment": self.NOTION_URL + f"#{entropy}",
            "backslash": rf"https://evil.example\@api.notion.com/v1/oauth/authorize?state={entropy}",
            "unknown-param": self.NOTION_URL + f"&session_blob={entropy}",
        }

        for shape, url in adversarial_urls.items():
            assert security.diagnose_oauth_url_credential(url) is not None, shape
            assert oauth_url_contains_credential(url) is True, shape

    def test_credential_shaped_parameter_name_is_omitted(self) -> None:
        raw_name = self.GITHUB_TOKEN
        url = f"https://api.notion.com/v1/oauth/authorize?{raw_name}=x"

        diagnostic = security.diagnose_oauth_url_credential(url)

        assert diagnostic is not None
        assert diagnostic.parameter is None
        assert raw_name not in json.dumps(diagnostic.as_dict(), sort_keys=True)

    def test_unrecognized_parameter_name_is_omitted_from_diagnostic_and_log(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        raw_name = "opaqueCredentialLikeKey"
        opaque_value = "Ab9_" * 64
        url = f"https://id.example-idp.com/authorize?{raw_name}={opaque_value}"

        diagnostic = security.diagnose_oauth_url_credential(url)

        assert diagnostic is not None
        assert diagnostic.rule == "exfil_query_length"
        assert diagnostic.parameter is None
        with caplog.at_level("WARNING", logger="kiro_crew.security"):
            assert oauth_url_contains_credential(url) is True
        output = json.dumps(diagnostic.as_dict(), sort_keys=True) + "\n" + caplog.text
        assert raw_name not in output
        assert opaque_value not in output

    def test_diagnostic_and_log_never_disclose_parameter_value(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        raw_value = self.GITHUB_TOKEN
        url = self.NOTION_URL.replace(self.STATE, raw_value, 1)

        diagnostic = security.diagnose_oauth_url_credential(url)
        assert diagnostic is not None
        assert diagnostic.rule == "fixed_credential_raw"
        assert diagnostic.component == "query_parameter"
        assert diagnostic.parameter == "state"

        with caplog.at_level("WARNING", logger="kiro_crew.security"):
            assert oauth_url_contains_credential(url) is True

        serialized = json.dumps(diagnostic.as_dict(), sort_keys=True)
        logged = "\n".join(record.getMessage() for record in caplog.records)
        digest = hashlib.sha256(raw_value.encode()).hexdigest()
        for output in (serialized, repr(diagnostic), logged):
            assert url not in output
            assert raw_value not in output
            assert raw_value[:16] not in output
            assert raw_value[-16:] not in output
            assert digest not in output

    @pytest.mark.parametrize(
        "url",
        [
            NOTION_URL.replace("api.notion.com", "evil.example", 1),
            NOTION_URL.replace("api.notion.com", "api.notion.com.evil.example", 1),
            NOTION_URL.replace("/v1/oauth/authorize", "/v1/oauth/authorize/extra", 1),
            NOTION_URL.replace("api.notion.com", "api.notion.com:443", 1),
            NOTION_URL.replace("https://", "http://", 1),
        ],
        ids=[
            "unapproved-host",
            "suffix-host",
            "path-prefix",
            "explicit-port",
            "http-scheme",
        ],
    )
    def test_unapproved_endpoint_fails_closed(self, url: str) -> None:
        assert oauth_url_contains_credential(url) is True

    def test_userinfo_embedded_token_fails_closed(self) -> None:
        url = f"https://{self.GITHUB_TOKEN}@api.notion.com/v1/oauth/authorize" "?state=ok"
        assert oauth_url_contains_credential(url) is True
        cleaned, warnings = redact_credentials(url)
        assert self.GITHUB_TOKEN not in cleaned
        assert warnings

    def test_backslash_authority_spoof_fails_closed(self) -> None:
        url = r"https://evil.com\@api.notion.com/v1/oauth/authorize?state=ok"
        assert oauth_url_contains_credential(url) is True

    def test_bare_aws_secret_in_hostname_fails_closed(self) -> None:
        assert len(self.BARE_AWS_SECRET_ALNUM) == 40
        url = f"https://{self.BARE_AWS_SECRET_ALNUM}.example/oauth/authorize" "?state=ok"
        assert oauth_url_contains_credential(url) is True

    def test_bare_aws_secret_in_fragment_fails_closed(self) -> None:
        assert len(self.BARE_AWS_SECRET) == 40
        url = f"{self.NOTION_URL}#{self.BARE_AWS_SECRET}"
        assert oauth_url_contains_credential(url) is True

    @pytest.mark.parametrize(
        "suffix",
        [
            ";session=ok?state=ok",
            "?state=ok#continue",
        ],
        ids=["path-params", "fragment"],
    )
    def test_path_params_and_fragments_fail_closed(self, suffix: str) -> None:
        url = "https://api.notion.com/v1/oauth/authorize" + suffix
        assert oauth_url_contains_credential(url) is True

    def test_unknown_query_parameter_with_secret_fails_closed(self) -> None:
        url = self.NOTION_URL + f"&session_blob={self.GITHUB_TOKEN}"
        assert oauth_url_contains_credential(url) is True
        self._assert_general_redactors_remove_secret(url, self.GITHUB_TOKEN)

    def test_duplicate_value_in_standard_and_unknown_param_fails_closed(self) -> None:
        url = self.NOTION_URL + f"&session_blob={self.CHALLENGE}"
        assert oauth_url_contains_credential(url) is True
        cleaned, warnings = redact_exfiltration_urls(url)
        assert cleaned != url
        assert warnings

    @pytest.mark.parametrize("parameter", ["state", "code_challenge"])
    @pytest.mark.parametrize(
        "credential",
        [
            "AKIA" "IOSFODNN7EXAMPLE",
            GITHUB_TOKEN,
        ],
        ids=["aws-access-key", "github-token"],
    )
    def test_fixed_credential_inside_recognized_param_fails_closed(
        self, parameter: str, credential: str
    ) -> None:
        original = self.STATE if parameter == "state" else self.CHALLENGE
        url = self.NOTION_URL.replace(original, f"prefix{credential}suffix", 1)
        assert oauth_url_contains_credential(url) is True
        self._assert_general_redactors_remove_secret(url, credential)

    def test_once_percent_decoded_fixed_credential_fails_closed(self) -> None:
        encoded_token = "%67%68%70%5F" + self.GITHUB_TOKEN.removeprefix("ghp_")
        url = self.NOTION_URL.replace(self.STATE, encoded_token, 1)
        assert oauth_url_contains_credential(url) is True

    def test_base64_encoded_credential_inside_state_fails_closed(self) -> None:
        encoded = base64.b64encode(self.GITHUB_TOKEN.encode()).decode()
        url = self.NOTION_URL.replace(self.STATE, encoded, 1)
        assert oauth_url_contains_credential(url) is True
        self._assert_general_redactors_remove_secret(url, encoded)

    def test_bare_aws_secret_inside_state_fails_closed_everywhere(self) -> None:
        assert len(self.BARE_AWS_SECRET) == 40
        # A base64-standard-alphabet run is a shape base64url cannot emit, so it
        # never inherits the entropy exemption -- no `+`/`/` reaches the blanked
        # set at an approved endpoint.
        assert "/" in self.BARE_AWS_SECRET
        url = self.NOTION_URL.replace(self.STATE, self.BARE_AWS_SECRET, 1)
        assert oauth_url_contains_credential(url) is True
        self._assert_general_redactors_remove_secret(url, self.BARE_AWS_SECRET)

    def test_percent_encoded_secret_alphabet_cannot_buy_the_exemption(self) -> None:
        # The markerless scan runs on the raw and decoded URL, so the shape test
        # must too: `%2F` must not launder a base64-standard run into exemption.
        url = self.NOTION_URL.replace(self.STATE, self.BARE_AWS_SECRET.replace("/", "%2F"), 1)
        assert oauth_url_contains_credential(url) is True

    @pytest.mark.parametrize(
        "encoded_slash",
        ["%2F", "%252F", "%25252F", "%2525252F"],
        ids=["single", "double", "triple", "over-budget"],
    )
    def test_no_encoding_depth_earns_the_entropy_exemption(self, encoded_slash: str) -> None:
        # One decode pass is not enough to JUDGE the shape: `%252F` decodes to
        # `%2F`, which still carries no literal `/`, so a raw-plus-one-decode test
        # would hand the exemption to a base64-standard run. Every decoded form
        # must keep the shape, and a value still decodable at the bound fails
        # closed.
        #
        # Scoped to the exemption predicate on purpose. Whether the banner then
        # WARNS on a doubly-encoded run is a separate, pre-existing property of
        # the markerless scan, which decodes the URL twice while
        # `_MAX_URL_DECODE_PASSES` is 3 -- so `%252F` goes unflagged even in a
        # parameter that was never exempt and at an unapproved endpoint. This
        # test must not claim to cover that gap.
        value = self.BARE_AWS_SECRET.replace("/", encoded_slash)
        assert security._oauth_entropy_value_is_protocol_shaped("state", value) is False

    def test_off_length_challenge_loses_the_s256_exemption(self) -> None:
        # An S256 challenge is base64url of a 32-byte digest: exactly 43 chars.
        # A 40-char value in that field is not a challenge shape.
        assert len(self.BARE_AWS_SECRET_ALNUM) == 40
        url = self.NOTION_URL.replace(self.CHALLENGE, self.BARE_AWS_SECRET_ALNUM, 1)
        assert oauth_url_contains_credential(url) is True

    @pytest.mark.parametrize("parameter", ["state", "code_challenge"])
    def test_markerless_secret_shape_is_banner_exempt_but_generically_redacted(
        self, parameter: str
    ) -> None:
        if parameter == "state":
            value = self.BARE_AWS_SECRET_ALNUM
            original = self.STATE
        else:
            value = self.BARE_AWS_SECRET_ALNUM + "abc"
            original = self.CHALLENGE
        url = self.NOTION_URL.replace(original, value, 1)

        # A markerless value that IS base64url-shaped (and, for the challenge,
        # the right length) is indistinguishable from normal OAuth entropy at
        # this approved parameter boundary. General output redactors keep the
        # heuristic because they do not inherit the banner-only exemption.
        assert oauth_url_contains_credential(url) is False
        self._assert_general_redactors_remove_secret(url, value)

    def test_bare_aws_secret_in_path_without_query_fails_closed(self) -> None:
        url = f"https://attacker.example/-{self.BARE_AWS_SECRET}"
        assert "?" not in url
        assert oauth_url_contains_credential(url) is True

    @pytest.mark.parametrize(
        "encoded_header",
        [
            "-----BEGIN+RSA+PRIVATE+KEY-----",
            "-----%42%45%47%49%4E%20RSA%20PRIVATE%20KEY-----",
        ],
        ids=["form-encoded-spaces", "percent-encoded-header"],
    )
    def test_encoded_pem_header_in_path_fails_closed_everywhere(self, encoded_header: str) -> None:
        url = f"https://attacker.example/upload/{encoded_header}/c2hvcnQ"
        assert oauth_url_contains_credential(url) is True

        scan_warnings = scan_exfiltration_urls(url)
        assert scan_warnings

        cleaned, redact_warnings = redact_exfiltration_urls(url)
        assert url not in cleaned
        assert redact_warnings == scan_warnings

    def test_multiply_percent_encoded_credential_in_path_fails_closed(
        self,
    ) -> None:
        """A single decode pass leaves a double-encoded payload intact
        ("%2542" -> "%42" -> "B"), so the scan decodes until stable."""
        from urllib.parse import quote

        once = quote("-----BEGIN RSA PRIVATE KEY-----", safe="-")
        for encoded in (once, quote(once, safe="-"), quote(quote(once, safe="-"), safe="-")):
            url = f"https://attacker.example/upload/{encoded}/x"
            assert oauth_url_contains_credential(url) is True

            scan_warnings = scan_exfiltration_urls(url)
            assert scan_warnings

            cleaned, redact_warnings = redact_exfiltration_urls(url)
            assert url not in cleaned
            assert redact_warnings == scan_warnings

    def test_credential_surviving_the_decode_budget_fails_closed(self) -> None:
        """A payload still decodable when the decode budget runs out is refused.

        The decode loop is bounded so a deliberately over-encoded URL cannot
        spin it. That bound must not be an escape hatch: a credential wrapped in
        more layers than the budget allows was never seen in plaintext, and the
        intermediate forms defeat both remaining checks -- the fixed-credential
        patterns match literal markers, not percent text, and the heavy-encoding
        detector needs 20+ CONSECUTIVE octets, which short escapes like "%2520"
        never form. Saturation is now treated as credential-bearing rather than
        clean, so the bound costs precision and never soundness.

        Parameterized on the budget on purpose: raising the cap is not a fix,
        and this must keep failing closed at whatever the cap becomes.
        """
        from urllib.parse import quote

        from kiro_crew.security import _MAX_URL_DECODE_PASSES

        encoded = quote("-----BEGIN RSA PRIVATE KEY-----", safe="-")
        for _ in range(_MAX_URL_DECODE_PASSES):
            encoded = quote(encoded, safe="-")
        url = f"https://attacker.example/upload/{encoded}/x"

        scan_warnings = scan_exfiltration_urls(url)
        assert scan_warnings

        cleaned, redact_warnings = redact_exfiltration_urls(url)
        assert url not in cleaned
        assert redact_warnings == scan_warnings

    def test_a_benign_singly_encoded_url_is_left_alone(self) -> None:
        """The saturation guard must not redact ordinary encoded URLs.

        One decode pass reaches a stable payload here, so the budget is never
        exhausted and the guard stays silent. This is the positive control for
        the test above: a fail-closed rule that fires on normal traffic would
        be indistinguishable from over-redaction.
        """
        url = "https://docs.example.com/guide?path=%2Fhome%2Fuser%2Freport.pdf"

        assert scan_exfiltration_urls(url) == []
        cleaned, warnings = redact_exfiltration_urls(url)
        assert cleaned == url
        assert warnings == []

    def test_heavy_percent_encoding_in_standard_param_fails_closed(self) -> None:
        url = self.NOTION_URL.replace(self.STATE, "%41" * 25, 1)
        assert oauth_url_contains_credential(url) is True
        cleaned, warnings = redact_exfiltration_urls(url)
        assert cleaned != url
        assert warnings

    def test_miro_mcp_authorize_endpoint_is_approved(self) -> None:
        """mcp.miro.com/authorize is a reporter-verified RFC 8414 endpoint
        -- a real PKCE consent URL there must pass the banner gate."""
        url = self.NOTION_URL.replace(
            "https://api.notion.com/v1/oauth/authorize",
            "https://mcp.miro.com/authorize",
            1,
        )
        assert oauth_url_contains_credential(url) is False


class TestSanitizedOAuthEndpoint:
    """``sanitized_oauth_endpoint`` names a rejected endpoint without leaking.

    The boolean gate alone leaves the user unable to tell WHICH URL tripped the
    scanner; this helper surfaces host+path only. The invariant under
    test: query values, fragments, userinfo, and credential-bearing paths never
    appear in the returned tuple.
    """

    GITHUB_TOKEN = "ghp_" "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"

    def test_returns_host_and_path_only(self) -> None:
        result = sanitized_oauth_endpoint(
            "https://idp.example/realms/dev/authorize"
            "?state=topsecretstate&code_challenge=alsosecret"
        )
        assert result == ("idp.example", "/realms/dev/authorize")

    def test_query_values_never_echoed(self) -> None:
        result = sanitized_oauth_endpoint(
            f"https://idp.example/authorize?token={self.GITHUB_TOKEN}"
        )
        assert result is not None
        assert self.GITHUB_TOKEN not in "".join(result)

    def test_host_is_lowercased(self) -> None:
        assert sanitized_oauth_endpoint("https://IdP.Example/Authorize") == (
            "idp.example",
            "/Authorize",  # paths are case-sensitive, only the host normalizes
        )

    def test_empty_path_defaults_to_root(self) -> None:
        assert sanitized_oauth_endpoint("https://idp.example") == ("idp.example", "/")

    def test_userinfo_authority_returns_none(self) -> None:
        """A userinfo-bearing authority is never named — raw or percent-encoded
        (user%3Apass%40host hides inside what urlparse reports as the
        hostname), mirroring the rejection gate's own check (GPT review)."""
        assert (
            sanitized_oauth_endpoint(f"https://{self.GITHUB_TOKEN}@idp.example/authorize") is None
        )
        assert (
            sanitized_oauth_endpoint("https://user%3Apass%40idp.example/authorize?state=x") is None
        )
        # DOUBLE-encoded userinfo (%2540) survives one decode pass; the "@"
        # check runs at every decode layer like the rest of the scan.
        assert (
            sanitized_oauth_endpoint("https://user%253Apass%2540idp.example/authorize?state=x")
            is None
        )

    def test_fragment_never_echoed(self) -> None:
        result = sanitized_oauth_endpoint("https://idp.example/authorize#fragmentsecret")
        assert result == ("idp.example", "/authorize")

    def test_credential_in_path_is_redacted(self) -> None:
        result = sanitized_oauth_endpoint(f"https://idp.example/{self.GITHUB_TOKEN}/authorize")
        assert result is not None
        host, path = result
        assert host == "idp.example"
        assert self.GITHUB_TOKEN not in path
        assert path == security.REDACTED_CREDENTIAL_TAG

    def test_format_character_split_credential_in_path_is_redacted(self) -> None:
        """Invisible format characters (U+200B) split a credential so no
        substring pattern matches, yet the browser renders the fragments
        visually reassembled — presence of ANY category-Cf character in a
        component is disqualifying on its own."""
        split_token = "\u200b".join(
            self.GITHUB_TOKEN[i : i + 8] for i in range(0, len(self.GITHUB_TOKEN), 8)
        )
        result = sanitized_oauth_endpoint(f"https://idp.example/{split_token}/authorize?x=1")
        assert result is not None
        host, path = result
        assert host == "idp.example"
        assert "\u200b" not in path
        assert path == security.REDACTED_CREDENTIAL_TAG

    def test_percent_encoded_format_character_in_path_is_redacted(self) -> None:
        """%E2%80%8B only becomes U+200B after a decode pass — the format
        character check runs on every decode layer like the rest of the scan."""
        encoded_zwsp = "%E2%80%8B"
        result = sanitized_oauth_endpoint(f"https://idp.example/auth{encoded_zwsp}orize?state=x")
        assert result is not None
        host, path = result
        assert host == "idp.example"
        assert path == security.REDACTED_CREDENTIAL_TAG

    def test_format_character_in_host_returns_none(self) -> None:
        """A host carrying an invisible format character is not a nameable
        identity — the helper falls back to the unnamed message."""
        assert sanitized_oauth_endpoint("https://idp\u200bevil.example/authorize") is None

    def test_percent_encoded_credential_in_path_is_redacted(self) -> None:
        encoded = "%67%68%70%5F" + self.GITHUB_TOKEN.removeprefix("ghp_")
        result = sanitized_oauth_endpoint(f"https://idp.example/{encoded}/authorize")
        assert result is not None
        host, path = result
        assert self.GITHUB_TOKEN not in path
        assert encoded not in path
        assert path == security.REDACTED_CREDENTIAL_TAG

    def test_double_percent_encoded_credential_in_path_is_redacted(self) -> None:
        """The rejection gate decodes up to _MAX_URL_DECODE_PASSES, so it
        rejects a DOUBLE-encoded credential on a deeper pass — the sanitizer
        must not echo bytes the gate refused (Opus review, worked case)."""
        double_encoded = "%2567%2568%2570%255F" + self.GITHUB_TOKEN.removeprefix("ghp_")
        result = sanitized_oauth_endpoint(f"https://idp.example/{double_encoded}/authorize")
        assert result is not None
        _, path = result
        assert self.GITHUB_TOKEN not in path
        assert double_encoded not in path
        assert path == security.REDACTED_CREDENTIAL_TAG

    def test_path_still_decodable_past_budget_is_redacted(self) -> None:
        """A path that keeps yielding new decode layers past the budget cannot
        be fully scanned — fail closed to the tag, mirroring the gate."""
        nested = "%2525252541"  # "A" percent-encoded 5 layers deep
        result = sanitized_oauth_endpoint(f"https://idp.example/{nested}/authorize")
        assert result is not None
        _, path = result
        assert path == security.REDACTED_CREDENTIAL_TAG

    def test_plus_delimited_private_key_in_path_is_redacted(self) -> None:
        """Form-encoded material delimits with "+"; the scan must fold it to
        spaces (unquote_plus) or a plus-separated private-key header slips
        through every decode layer unmatched (GPT review)."""
        result = sanitized_oauth_endpoint("https://idp.example/BEGIN+RSA+PRIVATE+KEY/authorize")
        assert result is not None
        _, path = result
        assert path == security.REDACTED_CREDENTIAL_TAG

    def test_credential_in_hostname_returns_none(self) -> None:
        """A credential smuggled into a DNS label (hyphens are DNS-legal, so a
        Slack-token-shaped label parses as a hostname) must not be echoed —
        a host is an identity, so the whole helper bails (GPT review)."""
        url = "https://xoxb-1234567890-AbCdEfGhIjKl.evil.example/authorize?state=x"
        assert sanitized_oauth_endpoint(url) is None

    def test_non_ascii_host_is_surfaced_as_idna_alabel(self) -> None:
        """An internationalized host surfaces in punycode A-label form: defuses
        homoglyph spoofing and matches the ASCII-only oauth_endpoints.json
        entry shape."""
        result = sanitized_oauth_endpoint("https://bücher.example/authorize")
        assert result is not None
        host, path = result
        assert host == "xn--bcher-kva.example"
        assert host.isascii()
        assert path == "/authorize"

    def test_fullwidth_host_normalizing_into_a_credential_returns_none(self) -> None:
        """IDNA nameprep folds fullwidth characters to ASCII, so a token-shaped
        fullwidth host can NORMALIZE INTO a credential the pre-IDNA scan could
        not match — the surfaced form must be re-scanned after every transform
        (GPT review)."""
        fullwidth = "ｘｏｘｂ－１２３４５６７８９０－ａｂｃｄｅｆｇｈｉｊｋｌ"
        assert sanitized_oauth_endpoint(f"https://{fullwidth}.evil.example/authorize") is None

    def test_overlong_path_is_truncated(self) -> None:
        # Hyphenated segments: no 40+ run of the base64 alphabet, so the path
        # is benign-long rather than entropy-suspicious — it truncates, not
        # redacts.
        long_path = "/seg-ment" * 40
        result = sanitized_oauth_endpoint(f"https://idp.example{long_path}")
        assert result is not None
        _, path = result
        assert len(path) == security._SANITIZED_OAUTH_PATH_MAX_LEN + 1
        assert path.endswith("…")

    def test_overlong_host_is_capped_with_a_marker(self) -> None:
        # 30-char labels: below the 40-char bare-run floor, so the host is
        # benign-long — it caps, not bails, and the cap is VISIBLE: a chopped
        # host that reads as a whole hostname names an endpoint that does not
        # exist, which is worse than an obviously partial one.
        long_host = ".".join(["a" * 30] * 9) + ".example"
        result = sanitized_oauth_endpoint(f"https://{long_host}/authorize")
        assert result is not None
        host, _ = result
        assert len(host) == security._SANITIZED_OAUTH_HOST_MAX_LEN + 1
        assert host.endswith("…")
        assert host[:-1] == long_host[: security._SANITIZED_OAUTH_HOST_MAX_LEN]

    def test_a_host_at_the_cap_is_not_marked(self) -> None:
        # Exactly the DNS maximum is a legal hostname; only an EXCESS is chopped.
        # 30-char labels again: no 40-char run that reads as a bare secret.
        at_cap = ".".join(["b" * 30] * 8) + ".abcde"
        assert len(at_cap) == security._SANITIZED_OAUTH_HOST_MAX_LEN
        result = sanitized_oauth_endpoint(f"https://{at_cap}/authorize")
        assert result == (at_cap, "/authorize")

    @pytest.mark.parametrize(
        "url",
        [
            "",
            "https://[bad-ipv6/x",
            "not a url at all",
            "https:///path-without-host",
        ],
        ids=["empty", "invalid-ipv6", "not-a-url", "no-host"],
    )
    def test_unparseable_urls_return_none(self, url: str) -> None:
        assert sanitized_oauth_endpoint(url) is None


def _long_state_query(*, extra: str = "") -> str:
    """A standard front-channel query whose opaque ``state`` pushes it past the
    long-query heuristic: rejected at any endpoint outside the allowlist, clean
    at an allowlisted one, because every parameter is a known OAuth name."""
    return (
        "?client_id=client123&response_type=code"
        "&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"
        "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        "&code_challenge_method=S256"
        "&state=" + ("a1B2c3D4" * 16) + extra
    )


class TestOAuthRejectionIsEndpointExemptible:
    """``oauth_rejection_is_endpoint_exemptible`` answers "would the allowlist fix it?".

    The counterfactual (``diagnose_oauth_url_credential(url,
    assume_approved_endpoint=True)``) re-runs the real gate with the endpoint
    treated as approved and nothing else relaxed. The operator-extension corpus
    is the positive set by definition: each entry is a URL the field rejected
    until its operator added the endpoint.
    """

    @pytest.mark.parametrize(
        ("url", "endpoint"),
        [(url, endpoint) for _, url, endpoint in OPERATOR_EXTENSION_OAUTH_URLS],
        ids=[name for name, _, _ in OPERATOR_EXTENSION_OAUTH_URLS],
    )
    def test_corpus_urls_are_rejected_today_and_pass_once_allowlisted(
        self, url: str, endpoint: tuple[str, str]
    ) -> None:
        assert security.diagnose_oauth_url_credential(url) is not None
        assert security.diagnose_oauth_url_credential(url, assume_approved_endpoint=True) is None
        assert security.oauth_rejection_is_endpoint_exemptible(url) is True

    @pytest.mark.parametrize(
        "url",
        [
            "https://idp.example.com/authorize?access_token=AKIAIOSFODNN7EXAMPLE",
            "https://idp.example.com/authorize" + _long_state_query(extra="#frag"),
            "https://idp.example.com/authorize;v=1" + _long_state_query(),
            f"https://user:pw@idp.example.com/authorize{_long_state_query()}",
            "http://idp.example.com/authorize" + _long_state_query(),
            "https://idp.example.com:8443/authorize" + _long_state_query(),
            "https://idp.example.com/authorize?state=" + ("%41" * 80),
        ],
        ids=[
            "fixed-credential-in-query",
            "fragment",
            "path-params",
            "userinfo",
            "http-scheme",
            "explicit-port",
            "heavy-percent-encoding",
        ],
    )
    def test_unconditional_rules_still_reject_under_the_assumption(self, url: str) -> None:
        assert security.diagnose_oauth_url_credential(url) is not None
        assert (
            security.diagnose_oauth_url_credential(url, assume_approved_endpoint=True) is not None
        )
        assert security.oauth_rejection_is_endpoint_exemptible(url) is False

    def test_a_url_the_gate_accepts_has_nothing_to_exempt(self) -> None:
        clean = "https://idp.example.com/authorize?state=abc&code_challenge_method=S256"
        assert security.diagnose_oauth_url_credential(clean) is None
        assert security.oauth_rejection_is_endpoint_exemptible(clean) is False

    def test_the_assumption_does_not_consult_the_operator_file(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The counterfactual is a pure re-run of the gate: no allowlist lookup,
        so no ``oauth_endpoint_extension_used`` audit event can fire for an
        endpoint nobody actually approved."""
        looked_up: list[tuple[str, str]] = []

        def spy(host: str, path: str) -> bool:
            looked_up.append((host, path))
            return False

        monkeypatch.setattr(security, "_approved_oauth_authorization_endpoint", spy)
        url = OPERATOR_EXTENSION_OAUTH_URLS[0][1]
        assert security.diagnose_oauth_url_credential(url, assume_approved_endpoint=True) is None
        assert looked_up == []
        assert security.diagnose_oauth_url_credential(url) is not None
        assert looked_up != []

    def test_the_default_verdict_is_unchanged(self) -> None:
        """``assume_approved_endpoint`` defaults off, so the boolean gate every
        caller uses is byte-for-byte the old one."""
        url = OPERATOR_EXTENSION_OAUTH_URLS[0][1]
        assert security.oauth_url_contains_credential(url) is True


class TestSanitizedOAuthEndpointDisplay:
    """``sanitized_oauth_endpoint_display`` is the COPY-READY contract.

    The diagnostic pair may legitimately carry a component that is not
    pasteable (redaction tag, ``…`` cap) or that the ``oauth_endpoints.json``
    loader would refuse (``localhost``, an IP literal, a percent-escape in the
    path); and a URL may be rejected for a reason the allowlist cannot clear
    (a fixed credential, a fragment, path parameters, ``http``, a port). A card
    that says "add THIS to oauth_endpoints.json" must hand back a string only
    when adding it would actually work. Every signature the helper judges is
    enumerated here with its verdict, so a widened or narrowed rule shows up as
    a specific row rather than a vague failure.
    """

    GITHUB_TOKEN = "ghp_" "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"
    Q = _long_state_query()

    @pytest.mark.parametrize(
        ("url", "expected"),
        [
            ("https://idp.example.com/authorize" + Q, "idp.example.com/authorize"),
            (
                "https://IdP.Example.COM/Realms/Dev/Authorize" + Q,
                "idp.example.com/Realms/Dev/Authorize",
            ),
            ("https://idp.example.com" + Q, "idp.example.com/"),
            ("https://bücher.example/authorize" + Q, "xn--bcher-kva.example/authorize"),
            # Operator-extension shapes the loader exists for: an Okta org, an
            # Auth0 tenant, a Keycloak realm, a tenant-scoped Entra path.
            (
                "https://dev-123456.okta.com/oauth2/default/v1/authorize" + Q,
                "dev-123456.okta.com/oauth2/default/v1/authorize",
            ),
            ("https://acme.us.auth0.com/authorize" + Q, "acme.us.auth0.com/authorize"),
            (
                "https://idp.example.com/realms/dev/protocol/openid-connect/auth" + Q,
                "idp.example.com/realms/dev/protocol/openid-connect/auth",
            ),
            (
                "https://login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize" + Q,
                "login.microsoftonline.com/tenant-id/oauth2/v2.0/authorize",
            ),
        ],
        ids=[
            "long-state-query-dropped",
            "host-lowercased-path-case-kept",
            "empty-path-becomes-slash",
            "idn-host-in-a-label-form",
            "okta-org",
            "auth0-tenant",
            "keycloak-realm",
            "entra-tenant-path",
        ],
    )
    def test_nameable_endpoints_come_back_as_host_slash_path(self, url: str, expected: str) -> None:
        assert sanitized_oauth_endpoint_display(url) == expected

    @pytest.mark.parametrize(
        ("name", "url", "endpoint"),
        OPERATOR_EXTENSION_OAUTH_URLS,
        ids=[name for name, _, _ in OPERATOR_EXTENSION_OAUTH_URLS],
    )
    def test_the_operator_extension_corpus_is_named_verbatim(
        self, name: str, url: str, endpoint: tuple[str, str]
    ) -> None:
        """The URLs the extension file exists for are exactly the ones the card
        must name, and the string it names is the entry that fixes them."""
        host, path = endpoint
        assert sanitized_oauth_endpoint_display(url) == f"{host}{path}"

    @pytest.mark.parametrize(
        "url",
        [
            # -- the diagnostic pair itself is None --
            "",
            "not a url at all",
            "https:///path-without-host",
            f"https://{GITHUB_TOKEN}@idp.example.com/authorize" + Q,
            "https://user%3Apass%40idp.example.com/authorize" + Q,
            "https://AKIAIOSFODNN7EXAMPLE.example.com/authorize" + Q,
            # -- pair is not pasteable: redaction tag / cap marker --
            "https://idp.example.com/AKIAIOSFODNN7EXAMPLE/authorize" + Q,
            "https://idp.example.com" + "/seg-ment" * 40 + Q,
            "https://" + ".".join(["a" * 30] * 9) + ".example/authorize" + Q,
            # -- the extension loader would refuse the host --
            "https://localhost/authorize" + Q,
            "https://10.0.0.1/authorize" + Q,
            "https://idp.example.com./authorize" + Q,
            "https://idp/authorize" + Q,
            # -- the extension loader would refuse the path --
            "https://idp.example.com/auth%20orize" + Q,
            "https://idp.example.com/../authorize" + Q,
            "https://idp.example.com/auth\\orize" + Q,
            # -- the allowlist could not clear the rejection --
            "https://idp.example.com/authorize?access_token=AKIAIOSFODNN7EXAMPLE",
            "https://idp.example.com/authorize" + _long_state_query(extra="#frag"),
            "https://idp.example.com/authorize;v=1" + Q,
            "http://idp.example.com/authorize" + Q,
            "https://idp.example.com:8443/authorize" + Q,
            "https://idp.example.com:443/authorize" + Q,
            # -- not rejected at all: nothing to name --
            "https://idp.example.com/authorize?state=x&code_challenge_method=S256",
        ],
        ids=[
            "empty",
            "not-a-url",
            "no-host",
            "userinfo",
            "encoded-userinfo",
            "credential-in-host",
            "credential-in-path-redacted",
            "overlong-path-capped",
            "overlong-host-capped",
            "localhost-no-letter-tld",
            "ipv4-literal",
            "trailing-dot-host",
            "single-label-host",
            "percent-escape-in-path",
            "dot-dot-in-path",
            "backslash-in-path",
            "fixed-credential-in-query",
            "fragment",
            "path-params",
            "http-scheme",
            "explicit-port",
            "explicit-default-port",
            "accepted-url",
        ],
    )
    def test_unnameable_endpoints_return_none(self, url: str) -> None:
        assert sanitized_oauth_endpoint_display(url) is None

    def test_the_display_string_is_exactly_what_the_loader_would_accept(self) -> None:
        """Contract closure: split the string back into (host, path) and run it
        through the SAME validators the extension loader applies, so the two
        can only drift together."""
        display = sanitized_oauth_endpoint_display(
            "https://idp.example.com/realms/dev/protocol/openid-connect/auth" + self.Q
        )
        assert display is not None
        host, _, rest = display.partition("/")
        path = "/" + rest
        assert security._OAUTH_EXTENSION_HOST_RE.fullmatch(host)
        assert security._valid_oauth_extension_path(path)
        assert security._validate_operator_oauth_entries(
            {"additional_authorization_endpoints": [{"host": host, "path": path}]}
        ) == frozenset({(host, path)})

    def test_the_raw_url_and_its_query_never_appear_in_the_display(self) -> None:
        url = "https://idp.example.com/authorize" + self.Q
        display = sanitized_oauth_endpoint_display(url)
        assert display == "idp.example.com/authorize"
        for secret in ("a1B2c3D4", "E9Melhoa2Owv", "client_id", "?", "https://"):
            assert secret not in display

    def test_a_redacted_path_is_refused_rather_than_joined(self) -> None:
        # The diagnostic pair is (host, tag): the tag must never be glued onto
        # the host as if it were a path a user could type.
        url = "https://idp.example.com/AKIAIOSFODNN7EXAMPLE/authorize" + self.Q
        assert sanitized_oauth_endpoint(url) == (
            "idp.example.com",
            security._REDACTED_CREDENTIAL_TAG,
        )
        assert sanitized_oauth_endpoint_display(url) is None


class TestOperatorOAuthEndpointExtension:
    """The keystone ``oauth_endpoints.json`` extends the OAuth endpoint set.

    The builtin ``_OAUTH_AUTHORIZATION_ENDPOINTS`` is deliberately code-owned;
    the operator's extension file is the only way to widen it, it fails soft to
    EMPTY on any defect, and every entry is strictly validated. HTTPS-only /
    no-explicit-port / exact-match semantics are identical to the builtin set
    and not relaxable via the file.
    """

    HOST = "acme.okta.com"
    PATH = "/oauth2/v1/authorize"
    CONSENT_URL = (
        "https://acme.okta.com/oauth2/v1/authorize"
        "?client_id=0oabcde12345FGHIJ697"
        "&response_type=code"
        "&scope=openid%20profile%20email%20offline_access"
        "&redirect_uri=https%3A%2F%2Fexample.com%2Fcallback"
        "&code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        "&code_challenge_method=S256"
        "&state=" + ("Zx9yW8vU" * 12)
    )

    @staticmethod
    def _write_extension(home: Path, entries: object) -> None:
        (home / "oauth_endpoints.json").write_text(
            (
                json.dumps({"additional_authorization_endpoints": entries})
                if not isinstance(entries, str)
                else entries
            ),
            encoding="utf-8",
        )

    @pytest.fixture(autouse=True)
    def _isolated_extension_state(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
        """Fresh home + fresh process-global audit/memo state for EVERY test.

        The dedupe set and the file memo are process-global by design; without
        a reset, tests exercising the real emit path would depend on execution
        order.
        """
        from kiro_crew import security

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path))
        monkeypatch.setattr(security, "_OAUTH_EXTENSION_AUDITED", set())
        monkeypatch.setattr(security, "_OAUTH_EXTENSION_MEMO", {})
        return tmp_path

    @pytest.fixture()
    def ext_home(self, _isolated_extension_state: Path) -> Path:
        return _isolated_extension_state

    # ── Loader: fail-soft postures ──

    def test_missing_file_yields_empty_set(self, ext_home: Path) -> None:
        from kiro_crew.security import _load_operator_oauth_endpoints

        assert _load_operator_oauth_endpoints() == frozenset()

    @pytest.mark.parametrize(
        "content",
        ["{not json", "[]", '"just a string"', '{"additional_authorization_endpoints": {}}'],
        ids=["corrupt", "non-object", "string", "key-not-list"],
    )
    def test_defective_file_yields_empty_set(self, ext_home: Path, content: str) -> None:
        from kiro_crew.security import _load_operator_oauth_endpoints

        self._write_extension(ext_home, content)
        assert _load_operator_oauth_endpoints() == frozenset()

    def test_valid_entry_accepted_and_host_lowercased(self, ext_home: Path) -> None:
        from kiro_crew.security import _load_operator_oauth_endpoints

        self._write_extension(ext_home, [{"host": "ACME.Okta.com", "path": self.PATH}])
        assert _load_operator_oauth_endpoints() == frozenset({(self.HOST, self.PATH)})

    def test_hand_edit_takes_effect_without_restart(self, ext_home: Path) -> None:
        """The check-time re-read contract: no gateway restart, no stale memo."""
        from kiro_crew.security import _load_operator_oauth_endpoints

        self._write_extension(ext_home, [{"host": self.HOST, "path": self.PATH}])
        assert _load_operator_oauth_endpoints() == frozenset({(self.HOST, self.PATH)})
        # Consult the memoized path once more before the edit.
        assert _load_operator_oauth_endpoints() == frozenset({(self.HOST, self.PATH)})

        self._write_extension(ext_home, [{"host": "other.idp.example", "path": "/authorize"}])
        # Force a distinct mtime even on filesystems with coarse timestamps.
        os.utime(
            ext_home / "oauth_endpoints.json",
            ns=(1_700_000_000_000_000_000, 1_700_000_000_000_000_000),
        )
        assert _load_operator_oauth_endpoints() == frozenset({("other.idp.example", "/authorize")})

        (ext_home / "oauth_endpoints.json").unlink()
        assert _load_operator_oauth_endpoints() == frozenset()

    # ── Loader: hostile entries are individually SKIPPED ──

    @pytest.mark.parametrize(
        "host",
        [
            "*.okta.com",
            "https://acme.okta.com",
            "acme.okta.com:443",
            "user@acme.okta.com",
            "acme.%6fkta.com",
            "acme .okta.com",
            "acme.okta.com\t",
            "acme\\okta.com",
            ".acme.okta.com",
            "acme.okta.com.",
            "192.168.1.1",
            "[::1]",
            "nodots",
            "acme.okta.123",
            "",
            "a" * 260 + ".com",
        ],
        ids=[
            "wildcard",
            "scheme-prefix",
            "explicit-port",
            "userinfo",
            "percent-escape",
            "whitespace",
            "trailing-tab",
            "backslash",
            "leading-dot",
            "trailing-dot",
            "ipv4-literal",
            "ipv6-literal",
            "no-dot",
            "digit-tld",
            "empty",
            "over-length",
        ],
    )
    def test_hostile_host_skipped(self, ext_home: Path, host: str) -> None:
        from kiro_crew.security import _load_operator_oauth_endpoints

        self._write_extension(ext_home, [{"host": host, "path": self.PATH}])
        assert _load_operator_oauth_endpoints() == frozenset()

    @pytest.mark.parametrize(
        "path",
        [
            "authorize",
            "/authorize?x=1",
            "/authorize#frag",
            "/authorize;p=1",
            "/autho%72ize",
            "/auth orize",
            "/auth\\orize",
            "/../authorize",
            "/" + "x" * 513,
        ],
        ids=[
            "no-leading-slash",
            "query",
            "fragment",
            "path-param",
            "percent-escape",
            "whitespace",
            "backslash",
            "dotdot",
            "over-length",
        ],
    )
    def test_hostile_path_skipped(self, ext_home: Path, path: str) -> None:
        from kiro_crew.security import _load_operator_oauth_endpoints

        self._write_extension(ext_home, [{"host": self.HOST, "path": path}])
        assert _load_operator_oauth_endpoints() == frozenset()

    @pytest.mark.parametrize(
        "entry",
        [
            "not-a-dict",
            {"host": 1, "path": "/a"},
            {"host": "ok.example.com", "path": None},
            {"host": "ok.example.com"},
            {},
        ],
        ids=["string-entry", "int-host", "none-path", "missing-path", "empty-dict"],
    )
    def test_non_string_entry_skipped(self, ext_home: Path, entry: object) -> None:
        from kiro_crew.security import _load_operator_oauth_endpoints

        self._write_extension(ext_home, [entry])
        assert _load_operator_oauth_endpoints() == frozenset()

    def test_one_bad_entry_does_not_poison_the_rest(self, ext_home: Path) -> None:
        from kiro_crew.security import _load_operator_oauth_endpoints

        self._write_extension(
            ext_home,
            [{"host": "*.evil.example", "path": "/a"}, {"host": self.HOST, "path": self.PATH}],
        )
        assert _load_operator_oauth_endpoints() == frozenset({(self.HOST, self.PATH)})

    def test_entry_cap_bounds_both_acceptance_and_iteration(self, ext_home: Path) -> None:
        from kiro_crew.security import (
            _ENDPOINT_EXTENSION_CAP,
            _load_operator_oauth_endpoints,
        )

        # Over-cap valid entries: only the first CAP are accepted. A valid
        # entry placed BEYOND the cap must be ignored even when earlier slots
        # were wasted on invalid entries — the slice bounds the iteration
        # itself, so a mangled file cannot amplify into an unbounded walk.
        entries: list[dict] = [
            {"host": f"idp{i}.example.com", "path": "/authorize"}
            for i in range(_ENDPOINT_EXTENSION_CAP + 10)
        ]
        self._write_extension(ext_home, entries)
        assert len(_load_operator_oauth_endpoints()) == _ENDPOINT_EXTENSION_CAP

        invalid_padding: list[dict] = [
            {"host": "*.invalid.example", "path": "/a"}
        ] * _ENDPOINT_EXTENSION_CAP
        self._write_extension(ext_home, invalid_padding + [{"host": self.HOST, "path": self.PATH}])
        assert _load_operator_oauth_endpoints() == frozenset()

    # ── Gate: the extension widens exactly the builtin exemption, nothing more ──

    def test_extended_endpoint_passes_previously_rejected_consent_url(self, ext_home: Path) -> None:
        # Fails closed with no file (the pre-extension behavior) …
        assert oauth_url_contains_credential(self.CONSENT_URL) is True
        # … and passes once the operator allowlists the exact endpoint.
        self._write_extension(ext_home, [{"host": self.HOST, "path": self.PATH}])
        assert oauth_url_contains_credential(self.CONSENT_URL) is False

    @pytest.mark.parametrize(
        "credential",
        ["AKIA" "IOSFODNN7EXAMPLE", "xoxb-1234567890-abcdefghijkl"],
        ids=["aws-access-key", "slack-token"],
    )
    def test_credential_at_extended_endpoint_still_rejected(
        self, ext_home: Path, credential: str
    ) -> None:
        self._write_extension(ext_home, [{"host": self.HOST, "path": self.PATH}])
        url = self.CONSENT_URL.replace("state=", f"state={credential}", 1)
        assert oauth_url_contains_credential(url) is True

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda u: u.replace("https://", "http://", 1),
            lambda u: u.replace("acme.okta.com", "acme.okta.com:443", 1),
            lambda u: u.replace("acme.okta.com", "other.idp.example", 1),
            lambda u: u.replace("acme.okta.com", "acme.okta.com.attacker.example", 1),
            lambda u: u.replace("/oauth2/v1/authorize", "/oauth2/v1/authorize/extra", 1),
        ],
        ids=["http-scheme", "explicit-port", "unknown-host", "lookalike-suffix", "path-suffix"],
    )
    def test_non_matching_urls_still_fail_closed(self, ext_home: Path, mutate) -> None:
        self._write_extension(ext_home, [{"host": self.HOST, "path": self.PATH}])
        assert oauth_url_contains_credential(mutate(self.CONSENT_URL)) is True

    def test_general_redactors_ignore_the_extension(self, ext_home: Path) -> None:
        # The carve-out stays banner-only: arbitrary model/agent text keeps the
        # full heuristics even for an operator-approved endpoint.
        self._write_extension(ext_home, [{"host": self.HOST, "path": self.PATH}])
        cleaned, warnings = redact_exfiltration_urls(self.CONSENT_URL)
        assert cleaned != self.CONSENT_URL
        assert warnings
        assert scan_exfiltration_urls(self.CONSENT_URL)

    # ── SEL audit ──

    def test_extension_approval_emits_audit_event(
        self, ext_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from kiro_crew import security

        self._write_extension(ext_home, [{"host": self.HOST, "path": self.PATH}])
        seen: list[tuple[str, str]] = []
        monkeypatch.setattr(
            security,
            "_emit_oauth_extension_used_event",
            lambda host, path: seen.append((host, path)),
        )
        assert oauth_url_contains_credential(self.CONSENT_URL) is False
        assert (self.HOST, self.PATH) in seen

    def test_builtin_approval_does_not_emit_audit_event(
        self, ext_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from kiro_crew import security

        seen: list[tuple[str, str]] = []
        monkeypatch.setattr(
            security,
            "_emit_oauth_extension_used_event",
            lambda host, path: seen.append((host, path)),
        )
        url = (
            "https://github.com/login/oauth/authorize"
            "?client_id=Iv1.a1b2c3d4e5f6g7h8&state=xyz789randomstring"
        )
        assert oauth_url_contains_credential(url) is False
        assert seen == []

    def test_audit_event_deduped_per_endpoint_but_not_across_endpoints(
        self, ext_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from kiro_crew import security
        from kiro_crew.security import exfil

        logged: list = []

        class _RecorderLog:
            def log(self, event: object) -> None:
                logged.append(event)

        monkeypatch.setattr(exfil, "SecurityEventLog", lambda: _RecorderLog())
        security._emit_oauth_extension_used_event(self.HOST, self.PATH)
        security._emit_oauth_extension_used_event(self.HOST, self.PATH)
        assert len(logged) == 1
        event = logged[0]
        assert event.event_type == "oauth_endpoint_extension_used"
        assert event.metadata["host"] == self.HOST
        assert event.metadata["path"] == self.PATH
        assert event.metadata["file"].endswith("oauth_endpoints.json")

        # A second DISTINCT endpoint still emits: dedupe is per (host, path).
        security._emit_oauth_extension_used_event("other.idp.example", "/authorize")
        assert len(logged) == 2

    def test_audit_failure_does_not_break_the_approval(
        self, ext_home: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from kiro_crew.security import exfil

        class _BrokenLog:
            def log(self, event: object) -> None:
                raise RuntimeError("SEL unavailable")

        monkeypatch.setattr(exfil, "SecurityEventLog", lambda: _BrokenLog())
        self._write_extension(ext_home, [{"host": self.HOST, "path": self.PATH}])
        assert oauth_url_contains_credential(self.CONSENT_URL) is False

    # ── Keystone fence: the agent cannot widen its own trust boundary ──

    @pytest.mark.parametrize("prefix", [".kiro/crew", ".kirocrew"])
    def test_extension_file_is_sensitive_under_every_home_prefix(self, prefix: str) -> None:
        from kiro_crew.security import is_sensitive_write_path

        assert is_sensitive_path(f"~/{prefix}/oauth_endpoints.json") is True
        # The write gate is a superset of the read gate; assert it directly so
        # the file-edit tool path is pinned too.
        assert is_sensitive_write_path(f"~/{prefix}/oauth_endpoints.json") is True

    # ── Corpus contract: operator-extension URLs ──

    @pytest.mark.parametrize(
        "provider,url,endpoint",
        OPERATOR_EXTENSION_OAUTH_URLS,
        ids=[p for p, _, _ in OPERATOR_EXTENSION_OAUTH_URLS],
    )
    def test_operator_extension_corpus_default_config_rejects(
        self, ext_home: Path, provider: str, url: str, endpoint: tuple[str, str]
    ) -> None:
        # Without the operator file these endpoints are NOT exempt — this is
        # what keeps the list out of LEGIT_OAUTH_URLS.
        assert oauth_url_contains_credential(url) is True

    @pytest.mark.parametrize(
        "provider,url,endpoint",
        OPERATOR_EXTENSION_OAUTH_URLS,
        ids=[p for p, _, _ in OPERATOR_EXTENSION_OAUTH_URLS],
    )
    def test_operator_extension_corpus_passes_with_allowlisted_endpoint(
        self, ext_home: Path, provider: str, url: str, endpoint: tuple[str, str]
    ) -> None:
        host, path = endpoint
        self._write_extension(ext_home, [{"host": host, "path": path}])
        assert oauth_url_contains_credential(url) is False
