"""The enterprise build's policy transport against a fake control plane.

The fake answers behind ``policy_distribution._open``, the one seam the network call goes
through, so nothing opens a socket. The sign-in is a real vault entry in a temporary data
home. Each enterprise failure is driven through boot to ``refuse_policy_boot`` to pin
that it exits with a message naming what failed.
"""

from __future__ import annotations

import io
import json
import ssl
import urllib.error
from datetime import datetime, timedelta, timezone
from email.message import Message

import pytest
from governance_distribution_helpers import _hermetic_governance_globals  # noqa: F401

from kiro_crew import enterprise_boot
from kiro_crew.auth.store import KasToken, TokenStore
from kiro_crew.platform import enterprise_policy_fetch as epf
from kiro_crew.platform import governance
from kiro_crew.platform import policy_distribution as pd
from kiro_crew.platform.context import PlatformCompositionError

_ARN = "arn:aws:codewhisperer:us-east-1:123456789012:profile/ABCDEFGHIJKL"
_EU_ARN = "arn:aws:codewhisperer:eu-central-1:123456789012:profile/ABCDEFGHIJKL"
_TOKEN = "fake-access-token-value"
_US_HOST = "https://management.us-east-1.kiro.dev/"
_EU_HOST = "https://management.eu-central-1.kiro.dev/"

_POLICY = """\
version: "0.1"
rules:
  - id: crew-channels
    capability: messaging_channel
    effect: allow
    match: ["slack"]
  - id: crew-channels-deny
    capability: messaging_channel
    effect: deny
    exclude: ["slack"]
  - id: other-client
    capability: shell
    effect: deny
"""


def _envelope(policy: str = _POLICY, *, status: str = "ENABLED", digest: str = "") -> bytes:
    hexdigest = epf.body_digest(policy)
    return json.dumps(
        {
            "enterpriseManagementStatus": status,
            "manifest": {
                "hash": "sha256:" + (digest or hexdigest),
                "versionId": "v1:" + hexdigest,
                "generatedAt": "2026-10-26T00:00:00Z",
            },
            "body": {"policy": policy, "configuration": []},
        }
    ).encode("utf-8")


class _Resp:
    def __init__(self, body: bytes, status: int = 200) -> None:
        self.status = status
        self._body = io.BytesIO(body)

    def read(self, n: int = -1) -> bytes:
        return self._body.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class FakeControlPlane:
    """Records each request and answers with the next configured reply."""

    def __init__(self) -> None:
        self.requests: list = []
        self.reply: object = _envelope()

    def __call__(self, req, timeout):
        self.requests.append(req)
        reply = self.reply
        if isinstance(reply, BaseException):
            raise reply
        if isinstance(reply, tuple):
            status, body = reply
            return _Resp(body, status)
        return _Resp(reply)  # type: ignore[arg-type]

    def payload(self, index: int = -1) -> dict:
        return json.loads(self.requests[index].data.decode("utf-8"))


def _http_error(code: int, body: dict) -> urllib.error.HTTPError:
    return urllib.error.HTTPError(
        _US_HOST, code, "error", Message(), io.BytesIO(json.dumps(body).encode("utf-8"))
    )


@pytest.fixture(name="vault")
def vault_fixture(tmp_path, monkeypatch):
    store = TokenStore(tmp_path / "data")
    monkeypatch.setattr("kiro_crew.auth.bridge.default_token_store", lambda: store)
    monkeypatch.delenv("KIRO_API_KEY", raising=False)

    def sign_in(profile_arn: str | None = _ARN, *, auth_method: str = "identity_center") -> None:
        store.save(
            KasToken(
                access_token=_TOKEN,
                expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
                provider="Enterprise",
                identity="external_idp" if auth_method == "external_idp" else "identity_center",
                profile_arn=profile_arn,
                auth_method=auth_method,
                token_endpoint="https://idp.example.invalid/token",
            )
        )

    return sign_in


@pytest.fixture(name="cps")
def cps_fixture(monkeypatch):
    fake = FakeControlPlane()
    monkeypatch.setattr(pd, "_open", fake)
    return fake


@pytest.fixture(name="enterprise")
def enterprise_fixture(monkeypatch):
    monkeypatch.setattr("kiro_crew.edition.EDITION", "enterprise")


def _boot_exit_message(capsys) -> str:
    """Boot as the CLI does and return what the refused boot printed."""
    with pytest.raises(SystemExit) as exited:
        try:
            governance.load_security_policy()
        except PlatformCompositionError as exc:
            enterprise_boot.refuse_policy_boot(exc)
            raise
    assert exited.value.code == enterprise_boot.EXIT_CODE
    err = capsys.readouterr().err
    assert _TOKEN not in err
    return err


def _request(etag: str = "") -> pd.FetchRequest:
    return pd.FetchRequest(url=pd.ENTERPRISE_POLICY_URL, etag=etag)


class TestSuccess:
    def test_boot_installs_the_translated_policy(self, enterprise, vault, cps):
        vault()
        ceiling = governance.load_security_policy()
        assert ceiling is not None
        doc = json.loads(pd.read_cache().body)
        assert doc["channels"] == {"members": {"mode": "allow", "allow": ["slack"]}}
        assert doc["distribution"] == {"refresh_interval_secs": 300}
        assert "shell" not in doc

    def test_the_request_is_the_signed_in_user_reading_as_crew(self, enterprise, vault, cps):
        vault()
        epf.fetch(_request())
        (req,) = cps.requests
        assert req.full_url == _US_HOST
        assert req.get_method() == "POST"
        headers = {k.lower(): v for k, v in req.header_items()}
        assert headers["authorization"] == f"Bearer {_TOKEN}"
        assert headers["x-amz-target"] == epf.TARGET
        assert headers["content-type"] == "application/x-amz-json-1.0"
        assert "tokentype" not in headers
        assert cps.payload() == {
            "profileArn": _ARN,
            "clientSurface": "CREW",
            "clientVersion": epf.__version__,
        }

    def test_an_external_idp_sign_in_sends_its_token_type(self, enterprise, vault, cps):
        vault(auth_method="external_idp")
        epf.fetch(_request())
        headers = {k.lower(): v for k, v in cps.requests[0].header_items()}
        assert headers["tokentype"] == "EXTERNAL_IDP"

    def test_an_unchanged_answer_keeps_the_cached_copy(self, enterprise, vault, cps):
        vault()
        first = epf.fetch(_request())
        cps.reply = json.dumps(
            {
                "enterpriseManagementStatus": "UNCHANGED",
                "manifest": {"versionId": first.etag.partition(":")[2]},
            }
        ).encode()
        second = epf.fetch(_request(first.etag))
        assert second.not_modified and second.etag == first.etag
        assert cps.payload()["manifestVersionId"] == first.etag.partition(":")[2]

    def test_another_profiles_cached_version_is_not_sent(self, enterprise, vault, cps):
        vault()
        first = epf.fetch(_request())
        vault(_EU_ARN)
        epf.fetch(_request(first.etag))
        assert "manifestVersionId" not in cps.payload()

    def test_disabled_answers_a_document_that_governs_nothing(self, enterprise, vault, cps):
        vault()
        cps.reply = json.dumps({"enterpriseManagementStatus": "DISABLED"}).encode()
        doc = json.loads(epf.fetch(_request()).body)
        assert "channels" not in doc
        assert governance.parse_policy(doc) is not None


class TestWrongHost:
    def test_the_host_comes_from_the_region_table(self, enterprise, vault, cps, monkeypatch):
        """No environment variable or local setting moves the address."""
        monkeypatch.setenv(pd.POLICY_URL_ENV, "https://elsewhere.example.invalid/p.json")
        monkeypatch.setenv(pd.POLICY_HEADERS_ENV, '{"Authorization": "Bearer other-secret"}')
        monkeypatch.setenv("KIROCREW_EM_ENDPOINT", "https://elsewhere.example.invalid/")
        vault(_EU_ARN)
        governance.load_security_policy()
        (req,) = cps.requests
        assert req.full_url == _EU_HOST
        assert req.get_header("Authorization") == f"Bearer {_TOKEN}"

    def test_an_unknown_region_still_uses_a_table_host(self, enterprise, vault, cps):
        vault("arn:aws:codewhisperer:ap-south-9:123456789012:profile/ABCDEFGHIJKL")
        epf.fetch(_request())
        assert cps.requests[0].full_url == _US_HOST

    def test_a_certificate_for_another_host_exits(self, enterprise, vault, cps, capsys):
        vault()
        cps.reply = urllib.error.URLError(ssl.SSLCertVerificationError("hostname mismatch"))
        err = _boot_exit_message(capsys)
        assert "TLS certificate did not verify" in err

    def test_a_redirect_exits(self, enterprise, vault, cps, capsys):
        vault()
        cps.reply = _http_error(302, {})
        assert "redirect" in _boot_exit_message(capsys)


class TestAuthFailure:
    def test_a_refused_token_exits(self, enterprise, vault, cps, capsys):
        vault()
        cps.reply = _http_error(
            403, {"__type": "com.amazon#AccessDeniedException", "message": f"bad {_TOKEN}"}
        )
        err = _boot_exit_message(capsys)
        assert "refused the Kiro sign-in" in err
        assert "AccessDeniedException" in err

    def test_no_sign_in_exits_without_calling_the_service(self, enterprise, vault, cps, capsys):
        err = _boot_exit_message(capsys)
        assert "no Kiro sign-in was found" in err
        assert "kirocrew kas login" in err
        assert cps.requests == []

    def test_an_api_key_does_not_stand_in_for_the_sign_in(
        self, enterprise, vault, cps, monkeypatch, capsys
    ):
        monkeypatch.setenv("KIRO_API_KEY", "an-api-key-value")
        assert "no Kiro sign-in was found" in _boot_exit_message(capsys)
        assert cps.requests == []

    def test_a_sign_in_with_no_profile_exits(self, enterprise, vault, cps, capsys):
        vault(None, auth_method="external_idp")
        assert "has no profile" in _boot_exit_message(capsys)

    def test_an_account_with_no_enterprise_management_exits(self, enterprise, vault, cps, capsys):
        vault()
        cps.reply = json.dumps({"enterpriseManagementStatus": "NOT_ELIGIBLE"}).encode()
        assert "has no enterprise management" in _boot_exit_message(capsys)


class TestUnreachable:
    @pytest.mark.parametrize(
        "error",
        [
            urllib.error.URLError(OSError("Name or service not known")),
            TimeoutError("timed out"),
            ConnectionRefusedError("refused"),
        ],
    )
    def test_an_unreachable_service_exits(self, enterprise, vault, cps, capsys, error):
        vault()
        cps.reply = error
        assert "could not be reached" in _boot_exit_message(capsys)

    def test_a_server_error_exits(self, enterprise, vault, cps, capsys):
        vault()
        cps.reply = _http_error(500, {"__type": "InternalServerException"})
        assert "HTTP 500 InternalServerException" in _boot_exit_message(capsys)


class TestBadFormat:
    @pytest.mark.parametrize(
        "body, expected",
        [
            (b"not json", "not JSON"),
            (b"[]", "not a JSON object"),
            (b'{"enterpriseManagementStatus": "MAYBE"}', "unknown status"),
            (b'{"enterpriseManagementStatus": "ENABLED", "body": {}}', "carries no policy"),
            (
                b'{"enterpriseManagementStatus": "UNCHANGED", "manifest": {"versionId": "v1:x"}}',
                "version not sent",
            ),
        ],
    )
    def test_a_malformed_answer_exits(self, enterprise, vault, cps, capsys, body, expected):
        vault()
        cps.reply = body
        assert expected in _boot_exit_message(capsys)

    def test_a_policy_that_is_not_yaml_rules_exits(self, enterprise, vault, cps, capsys):
        vault()
        cps.reply = _envelope("rules: {not: a list}")
        assert "cannot be applied" in _boot_exit_message(capsys)

    def test_an_unrepresentable_policy_exits(self, enterprise, vault, cps, capsys):
        vault()
        cps.reply = _envelope(
            "rules:\n"
            "  - {capability: messaging_channel, effect: deny, exclude: ['s*']}\n"
            "  - {capability: messaging_channel, effect: deny, match: ['slack']}\n"
        )
        assert "inside an allowed glob" in _boot_exit_message(capsys)

    def test_an_oversized_answer_exits(self, enterprise, vault, cps, capsys):
        vault()
        cps.reply = b"x" * (epf.MAX_ENVELOPE_BYTES + 1)
        assert "exceeds" in _boot_exit_message(capsys)


class TestShaMismatch:
    def test_a_body_that_does_not_match_its_hash_exits(self, enterprise, vault, cps, capsys):
        vault()
        cps.reply = _envelope(digest="0" * 64)
        assert "does not match its own sha256 hash" in _boot_exit_message(capsys)

    def test_an_answer_with_no_hash_is_accepted(self, enterprise, vault, cps):
        vault()
        cps.reply = json.dumps(
            {"enterpriseManagementStatus": "ENABLED", "body": {"policy": _POLICY}}
        ).encode()
        doc = json.loads(epf.fetch(_request()).body)
        assert doc["channels"]["members"]["allow"] == ["slack"]

    def test_the_hash_covers_the_configuration(self, enterprise, vault, cps, capsys):
        vault()
        envelope = json.loads(_envelope())
        envelope["body"]["configuration"] = [
            {"key": "k", "value": "v", "source": "s", "composeBehavior": "c"}
        ]
        cps.reply = json.dumps(envelope).encode()
        assert "sha256" in _boot_exit_message(capsys)


class TestProfileBoundCache:
    def test_a_profile_switch_does_not_serve_the_previous_cache(
        self, enterprise, vault, cps, monkeypatch
    ):
        """A fresh cache from another profile is not the shortcut: the new profile is read."""
        monkeypatch.setattr(pd, "_claim_fetch_slot", lambda window: True)  # a restart
        vault()
        governance.load_security_policy()
        vault(_EU_ARN)
        cps.reply = _envelope("rules: []\n")
        governance.load_security_policy()
        assert [r.full_url for r in cps.requests] == [_US_HOST, _EU_HOST]
        assert "channels" not in json.loads(pd.read_cache().body)

    def test_the_same_profile_is_served_from_a_fresh_cache(self, enterprise, vault, cps):
        vault()
        governance.load_security_policy()
        governance.load_security_policy()
        assert len(cps.requests) == 1

    def test_another_profiles_cache_is_not_the_outage_fallback(
        self, enterprise, vault, cps, capsys, monkeypatch
    ):
        monkeypatch.setattr(pd, "_claim_fetch_slot", lambda window: True)  # a restart
        vault()
        governance.load_security_policy()
        vault(_EU_ARN)
        cps.reply = TimeoutError("down")
        assert "could not be reached" in _boot_exit_message(capsys)

    def test_another_processes_cache_for_another_profile_is_not_adopted(
        self, enterprise, vault, cps
    ):
        """The concurrent-writer handoff checks the profile as well as the source."""
        from kiro_crew.platform import policy_distribution_boot as boot

        vault()
        governance.load_security_policy()
        winner = pd.read_cache()
        vault(_EU_ARN)
        dist = pd.resolve_distribution()
        outcome = boot._load_from_cached_winner(dist, winner)
        assert outcome.ceiling is None
        assert "another sign-in" in outcome.reason


class TestTranslation:
    @pytest.mark.parametrize(
        "excludes, expected",
        [
            ([["s*"], ["slack"]], ["slack"]),
            ([["slack", "teams"], ["SLACK"]], ["slack"]),
            ([["s*"], ["s*", "teams"]], ["s*"]),
            ([["slack"], ["teams"]], []),
        ],
    )
    def test_excludes_intersect_by_what_they_admit(self, excludes, expected):
        from kiro_crew.platform import enterprise_policy_translate as t

        rules = [
            {"capability": "messaging_channel", "effect": "deny", "exclude": e} for e in excludes
        ]
        assert t.ruleset(rules, "messaging_channel") == {"mode": "allow", "allow": expected}

    def test_a_denied_glob_removes_the_literals_it_matches(self):
        from kiro_crew.platform import enterprise_policy_translate as t

        rules = [
            {"capability": "messaging_channel", "effect": "deny", "exclude": ["slack", "teams"]},
            {"capability": "messaging_channel", "effect": "deny", "match": ["s*"]},
        ]
        assert t.ruleset(rules, "messaging_channel") == {"mode": "allow", "allow": ["teams"]}

    def test_a_denied_glob_beside_an_allowed_glob_is_refused(self):
        from kiro_crew.platform import enterprise_policy_translate as t

        rules = [
            {"capability": "messaging_channel", "effect": "deny", "exclude": ["t*"]},
            {"capability": "messaging_channel", "effect": "deny", "match": ["s*"]},
        ]
        with pytest.raises(t.Unrepresentable):
            t.ruleset(rules, "messaging_channel")

    def test_two_different_globs_are_refused(self):
        from kiro_crew.platform import enterprise_policy_translate as t

        rules = [
            {"capability": "messaging_channel", "effect": "deny", "exclude": e}
            for e in (["s*"], ["*k"])
        ]
        with pytest.raises(t.Unrepresentable):
            t.ruleset(rules, "messaging_channel")


class TestSignInCommands:
    def _main(self, monkeypatch, tmp_path, argv):
        from kiro_crew import cli

        def failed_policy(_cfg):
            raise PlatformCompositionError("no Kiro sign-in was found")

        monkeypatch.setenv("KIROCREW_HOME", str(tmp_path))
        monkeypatch.setattr(cli, "boot_platform", failed_policy)
        monkeypatch.setattr(cli, "maybe_reexec", lambda _argv: None)
        monkeypatch.setattr(
            cli.platform_compat, "limit_malloc_arenas", cli.platform_compat.MallocArenaCap
        )
        monkeypatch.setattr(cli, "_setup_cli_logging", lambda *_args: None)
        monkeypatch.setattr(cli.sys, "argv", ["kirocrew", *argv])
        return cli

    def test_kas_login_runs_when_the_policy_load_fails(self, enterprise, monkeypatch, tmp_path):
        cli = self._main(monkeypatch, tmp_path, ["kas", "whoami"])
        ran: list = []
        monkeypatch.setattr(
            "kiro_crew.cli_kas_login.kas_login_cmd", lambda args: ran.append(args.kas_action) or 0
        )
        with pytest.raises(SystemExit) as exited:
            cli.main()
        assert exited.value.code in (0, None)
        assert ran == ["whoami"]

    def test_other_commands_still_exit(self, enterprise, monkeypatch, tmp_path, capsys):
        cli = self._main(monkeypatch, tmp_path, ["kas", "status"])
        with pytest.raises(SystemExit) as exited:
            cli.main()
        assert exited.value.code == enterprise_boot.EXIT_CODE
        assert "no Kiro sign-in was found" in capsys.readouterr().err

    def test_oss_does_not_exempt_the_sign_in_verbs(self, monkeypatch, tmp_path):
        cli = self._main(monkeypatch, tmp_path, ["kas", "whoami"])
        with pytest.raises(PlatformCompositionError):
            cli.main()


class TestOss:
    def test_oss_refuses_the_scheme(self, vault, cps):
        vault()
        with pytest.raises(PlatformCompositionError, match="only in an enterprise build"):
            epf.fetch(_request())
        assert cps.requests == []

    def test_oss_boot_is_unchanged(self, vault, cps):
        vault()
        assert governance.load_security_policy() is None
        assert cps.requests == []

    def test_oss_naming_the_scheme_is_a_configuration_error(self, vault, cps, monkeypatch):
        monkeypatch.setenv(pd.POLICY_URL_ENV, pd.ENTERPRISE_POLICY_URL)
        with pytest.raises(PlatformCompositionError, match="only in an enterprise build"):
            governance.load_security_policy()
        assert cps.requests == []
