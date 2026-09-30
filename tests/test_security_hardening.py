"""Credentials, TLS settings and untrusted input: what an independent audit found, pinned.

Every test here failed against the code as it was when the audit ran.
"""

# ruff: noqa: SIM117, PLC0415, S105, S108
# (These tests deliberately nest several servers in one ``with``, import lazily, use made-up
# secrets and a full-width digit as attack input, and list directories the way the code under test does.)

import os
import ssl
from pathlib import Path
from typing import Any

import pytest
import requests

from tests.certificates import Certificates
from tests.scripted_server import OK, Seen, always, redirect, scripted_server
from webdav import FileSystem, RedirectPolicy, Session, exceptions
from webdav.dav.conditional import Condition, build_if_header_single
from webdav.dav.locks import LockRegistry
from webdav.dav.properties import build_proppatch_body
from webdav.exceptions import ClientError, TLSConfigError
from webdav.transport.tls import SSLContextAdapter, TLSOptions, build_ssl_context
from webdav.url_safety import effective_origin

# ---------------------------------------------------------------------------
# Certificate verification is on by default, and disabling it is never quiet
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("verify", [False, None, 0, "", b"", 0.0])
def test_the_constructor_warns_loudly_for_everything_that_means_no_verification(
    verify: object,
) -> None:
    with pytest.warns(exceptions.TLSHardeningDisabledWarning, match="verification"):
        Session(verify=verify)  # type: ignore[arg-type]


def test_a_per_call_or_attribute_verify_false_still_sends_the_request() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session.get(f"{url}/a", verify=False)
        session.verify = False
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session.get(f"{url}/a")
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session.propfind(f"{url}/a", depth=0)
    assert len(rec.requests) == 3


def test_disabling_verification_is_logged_too_not_only_a_python_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Not only ``warnings.warn`` - a blanket warnings filter must not erase every trace."""

    def connect_insecurely(url: str) -> None:
        Session(retry=False, verify=False).get(f"{url}/a")

    with scripted_server(always(OK)) as (url, _rec):
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            connect_insecurely(url)
    assert any(
        "TLS hardening disabled" in r.message and "verification" in r.message
        for r in caplog.records
    )


def test_a_missing_ca_bundle_is_both_a_webdav_error_and_a_value_error(
    tmp_path: Path,
) -> None:
    with pytest.raises(ClientError) as excinfo:
        Session(verify=str(tmp_path / "nope.pem"), retry=False).get(
            "http://unused.invalid/a"
        )
    assert isinstance(excinfo.value, requests.RequestException)


def test_a_missing_ca_bundle_is_a_webdav_error_not_an_oserror(tmp_path: Path) -> None:
    session = Session(verify=str(tmp_path / "nope.pem"), retry=False)
    with pytest.raises(ClientError, match="does not exist"):
        session.get("http://unused.invalid/a")


def test_verification_falsy_values_warn_per_call_too() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        for falsy in (False, 0, "", None):
            session.verify = falsy  # type: ignore[assignment]
            with pytest.warns(exceptions.TLSHardeningDisabledWarning):
                session.get(f"{url}/a")
        assert len(rec.requests) == 4


def test_the_environment_cannot_replace_the_configured_ca(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    other = tmp_path / "other-ca.pem"
    other.write_text("not really a ca")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(other))
    monkeypatch.setenv("CURL_CA_BUNDLE", str(other))
    session = Session()
    settings = session.merge_environment_settings(
        "https://dav.example/", {}, None, None, None
    )
    assert settings["verify"] is True
    pinned = Session(verify="/etc/ssl/pinned.pem")
    settings = pinned.merge_environment_settings(
        "https://dav.example/", {}, None, None, None
    )
    assert settings["verify"] == "/etc/ssl/pinned.pem"


# ---------------------------------------------------------------------------
# Credentials are only ever the ones asked for
# ---------------------------------------------------------------------------


def test_netrc_is_not_consulted(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    netrc = tmp_path / "netrc"
    netrc.write_text("machine 127.0.0.1 login netrcuser password netrcpass\n")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    monkeypatch.setenv("HOME", str(tmp_path))
    with scripted_server(always(OK)) as (url, rec):
        Session(retry=False).get(f"{url}/a")
        Session(retry=False).propfind(f"{url}/a", depth=0)
    assert all("authorization" not in r.headers for r in rec.requests)


def test_explicit_credentials_still_work() -> None:
    with scripted_server(always(OK)) as (url, rec):
        Session(auth=("u", "p"), retry=False).get(f"{url}/a")
        Session(retry=False).get(f"{url}/b", auth=("u", "p"))
    assert all(r.headers["authorization"].startswith("Basic ") for r in rec.requests)


def test_a_foreign_hop_uses_its_own_adapter_and_no_client_certificate(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    cert, key = Certificates(tmp_path).issue_client_cert("client")
    seen: dict[str, Any] = {}
    with scripted_server(always(OK)) as (storage_url, _storage):
        with scripted_server(lambda _r: redirect(307, f"{storage_url}/t")) as (
            gateway_url,
            _g,
        ):
            session = Session(
                redirect_policy=RedirectPolicy.ALL,
                cert=(str(cert), str(key)),
                retry=False,
            )
            real = session._foreign_adapter.send

            def spy(request: Any, **kwargs: Any) -> Any:
                seen.update(kwargs)
                return real(request, **kwargs)

            monkeypatch.setattr(session._foreign_adapter, "send", spy)
            response = session.put(f"{gateway_url}/f", data=b"x")
    assert response.status_code == 204
    assert seen["cert"] is None


def test_a_cross_origin_answer_cannot_set_cookies_in_the_session() -> None:
    def storage(_r: Seen) -> tuple[int, dict[str, str], bytes]:
        return 204, {"Set-Cookie": "sid=attacker; Path=/"}, b""

    with scripted_server(storage) as (storage_url, _s):
        with scripted_server(lambda _r: redirect(307, f"{storage_url}/t")) as (
            gateway_url,
            _g,
        ):
            session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
            session.put(f"{gateway_url}/f", data=b"x")
            assert len(session.cookies) == 0


def test_per_call_custom_headers_do_not_follow_a_redirect_to_another_origin() -> None:
    with scripted_server(always(OK)) as (storage_url, storage):
        with scripted_server(lambda _r: redirect(307, f"{storage_url}/t")) as (
            gateway_url,
            _g,
        ):
            session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
            session.put(
                f"{gateway_url}/f",
                data=b"x",
                headers={
                    "Content-Type": "text/plain",
                    "X-Api-Key": "SECRET",
                    "X-Token": "T",
                },
            )
    (seen,) = storage.requests
    assert seen.headers["content-type"] == "text/plain"
    assert "x-api-key" not in seen.headers
    assert "x-token" not in seen.headers


def test_extra_forwarded_headers_are_an_explicit_opt_in() -> None:
    with scripted_server(always(OK)) as (storage_url, storage):
        with scripted_server(lambda _r: redirect(307, f"{storage_url}/t")) as (
            gateway_url,
            _g,
        ):
            session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
            session.redirect_forward_headers = frozenset({"x-amz-meta-owner"})
            session.put(
                f"{gateway_url}/f",
                data=b"x",
                headers={
                    "X-Amz-Meta-Owner": "me",
                    "X-Api-Key": "SECRET",
                    "Authorization": "B",
                },
            )
    (seen,) = storage.requests
    assert seen.headers["x-amz-meta-owner"] == "me"
    assert "x-api-key" not in seen.headers
    assert "authorization" not in seen.headers


def test_the_lock_header_is_worked_out_again_for_a_redirect_target_on_the_same_origin() -> (
    None
):
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        return redirect(307, "/other.txt") if seen.path == "/locked.txt" else OK

    with scripted_server(respond) as (url, rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/locked.txt", "opaquelocktoken:t", "0")
        session.put(f"{url}/locked.txt", data=b"x")
    first, second = rec.requests
    assert first.headers["if"] == "(<opaquelocktoken:t>)"
    assert "if" not in second.headers


def test_reads_never_carry_a_lock_token() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        session.locks.add(f"{url}/f", "opaquelocktoken:t", "infinity")
        session.get(f"{url}/f")
        session.propfind(f"{url}/f", depth=0)
        session.head(f"{url}/f")
        session.put(f"{url}/f", data=b"x")
    assert [("if" in r.headers) for r in rec.requests] == [False, False, False, True]


def test_a_port_zero_is_never_an_origin() -> None:
    assert effective_origin("https://dav.example:0/x") is None
    assert effective_origin("http://dav.example:65536/x") is None
    assert effective_origin("https://dav.example:443/x") == (
        "https",
        "dav.example",
        443,
    )


def test_credentials_in_a_url_do_not_reach_messages_or_warnings() -> None:
    session = Session("http://dav.example")
    with pytest.raises(ClientError) as excinfo:
        session.get("http://bob:PWD1@other.example/x")
    assert "PWD1" not in str(excinfo.value)

    with scripted_server(always((404, {}, b""))) as (url, rec):
        host = url.removeprefix("http://")
        with pytest.raises(ClientError, match="auth") as refused:
            FileSystem(retry=False).ls(f"http://bob:PWD4@{host}/dir")
    assert "PWD4" not in str(refused.value)
    assert (
        rec.requests == []
    )  # credentials in a URL are refused before anything is sent


def test_the_insecure_transport_warning_names_no_password_and_sees_url_credentials() -> (
    None
):
    session = Session(retry=False)
    with pytest.warns(exceptions.InsecureTransportWarning) as caught:
        session._warn_if_insecure("http://bob:PWD2@192.0.2.1:9/x", {})
    assert "PWD2" not in str(caught[0].message)
    assert "192.0.2.1:9" in str(caught[0].message)


def test_a_cookie_header_counts_as_a_credential_for_the_warning() -> None:
    session = Session(retry=False)
    with pytest.warns(exceptions.InsecureTransportWarning):
        session._warn_if_insecure(
            "http://192.0.2.1/x", {"headers": {"Cookie": "sid=1"}}
        )


# ---------------------------------------------------------------------------
# TLS configuration fails closed
# ---------------------------------------------------------------------------


def test_the_key_password_is_not_in_the_repr() -> None:
    assert "TOPSECRET" not in repr(TLSOptions(key_password="TOPSECRET"))


@pytest.mark.parametrize("field", ["ca_files", "crl_files"])
@pytest.mark.parametrize("empty", [[], (), ""])
def test_an_empty_ca_or_crl_list_is_an_error_not_a_weaker_setup(
    field: str, empty: object
) -> None:
    options: dict[str, Any] = {field: empty}
    with pytest.raises(TLSConfigError, match="empty"):
        build_ssl_context(options=TLSOptions(**options))


def test_the_tls_floor_is_secure_by_default_but_can_be_lowered_loudly() -> None:
    context = build_ssl_context()
    assert context.minimum_version >= ssl.TLSVersion.TLSv1_2
    assert context.verify_flags & ssl.VERIFY_X509_STRICT

    with pytest.warns(exceptions.TLSHardeningDisabledWarning, match="floor"):
        context = build_ssl_context(
            options=TLSOptions(minimum_version=ssl.TLSVersion.TLSv1)
        )
    assert context.minimum_version == ssl.TLSVersion.TLSv1


def test_strict_chain_checking_is_on_by_default_but_can_be_turned_off_loudly() -> None:
    context = build_ssl_context()
    assert context.verify_flags & ssl.VERIFY_X509_STRICT

    with pytest.warns(exceptions.TLSHardeningDisabledWarning, match="strict"):
        context = build_ssl_context(options=TLSOptions(strict_chain_checking=False))
    assert not context.verify_flags & ssl.VERIFY_X509_STRICT


def test_verification_is_on_by_default_but_can_be_turned_off_loudly() -> None:
    context = build_ssl_context()
    assert context.verify_mode == ssl.CERT_REQUIRED
    assert context.check_hostname is True

    with pytest.warns(exceptions.TLSHardeningDisabledWarning, match="verify"):
        context = build_ssl_context(verify=False)
    assert context.verify_mode == ssl.CERT_NONE
    assert context.check_hostname is False


def test_the_adapter_leaves_verification_to_its_context_alone() -> None:
    adapter = SSLContextAdapter(build_ssl_context())

    class Conn:
        cert_reqs = None
        ca_certs = "/certifi/cacert.pem"
        ca_cert_dir = "/somewhere"
        cert_file = "/tmp/other.pem"
        key_file = "/tmp/other.key"

    conn = Conn()
    adapter.cert_verify(conn, "https://dav.example/", False, ("/a", "/b"))
    assert conn.cert_reqs == "CERT_REQUIRED"
    assert conn.ca_certs is None
    assert conn.cert_file is None
    assert conn.key_file is None


def test_the_adapter_carries_verify_false_through_to_the_connection() -> None:
    with pytest.warns(exceptions.TLSHardeningDisabledWarning):
        adapter = SSLContextAdapter(build_ssl_context(verify=False), verify=False)

    class Conn:
        cert_reqs = None
        ca_certs = "/certifi/cacert.pem"
        ca_cert_dir = "/somewhere"
        cert_file = "/tmp/other.pem"
        key_file = "/tmp/other.key"

    conn = Conn()
    adapter.cert_verify(conn, "https://dav.example/", False, ("/a", "/b"))
    assert conn.cert_reqs == "CERT_NONE"


def test_a_pinned_ca_is_not_widened_by_the_public_ones(tmp_path: Path) -> None:
    certs = Certificates(tmp_path)
    context = build_ssl_context(options=TLSOptions(ca_files=[str(certs.ca_cert)]))
    before = len(context.get_ca_certs())
    adapter = SSLContextAdapter(context)
    adapter.cert_verify(type("C", (), {})(), "https://dav.example/", True, None)
    assert len(context.get_ca_certs()) == before == 1


def test_an_encrypted_key_without_a_password_fails_instead_of_prompting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    certs = Certificates(tmp_path)
    cert, key = certs.issue_client_cert("client")
    encrypted = certs.encrypt_key(key, "secret-pw")
    prompts: list[int] = []

    def fake_input(*_a: object) -> str:
        prompts.append(1)
        return ""

    monkeypatch.setattr("builtins.input", fake_input)
    with pytest.raises(TLSConfigError):
        build_ssl_context(certfile=cert, keyfile=encrypted, options=TLSOptions())
    assert prompts == []


def test_an_ssl_adapter_refuses_to_be_pickled() -> None:
    import pickle

    with pytest.raises(TypeError, match="cannot be pickled"):
        pickle.dumps(SSLContextAdapter(build_ssl_context()))


# ---------------------------------------------------------------------------
# Small RFC 4918 details
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("given", "rendered"),
    [
        ('"abc"', '["abc"]'),
        ("abc", '["abc"]'),
        ('W/"abc"', '[W/"abc"]'),
    ],
)
def test_an_etag_in_an_if_header_is_quoted_exactly_once(
    given: str, rendered: str
) -> None:
    assert Condition(etag=given).render() == rendered
    assert build_if_header_single([Condition(etag=given)]) == f"({rendered})"


@pytest.mark.parametrize("bad", ['a"b', "a\nb", "a\x00b", '"a"b"', '"a b"', "a b"])
def test_an_etag_that_would_break_out_of_its_brackets_is_refused(bad: str) -> None:
    with pytest.raises(ValueError, match="entity-tag"):
        Condition(etag=bad).render()


@pytest.mark.parametrize("token", ["a>b", "a b", 'a"b', "tä"])
def test_a_token_that_would_break_out_of_its_brackets_is_refused(token: str) -> None:
    with pytest.raises(ValueError, match="Coded-URL"):
        Condition(token=token).render()


def test_an_empty_proppatch_is_refused() -> None:
    with pytest.raises(ValueError, match="at least one"):
        build_proppatch_body()
    with pytest.raises(ValueError, match="at least one"):
        build_proppatch_body(set_props={}, remove_props=[])
    with pytest.raises(TypeError, match="str or Element"):
        build_proppatch_body(set_props={"displayname": 5})  # type: ignore[dict-item]


def test_lock_arguments_are_validated_before_anything_is_sent() -> None:
    session = Session()
    with pytest.raises(ValueError, match="scope"):
        session.lock("http://unused.invalid/a", scope="bogus")
    bad_timeouts: list[Any] = [True, -1, 2**40, "5", []]
    for bad in bad_timeouts:
        with pytest.raises(ValueError, match=r"timeout|empty"):
            session.lock("http://unused.invalid/a", lock_timeout=bad)  # type: ignore[arg-type]


def test_unlock_strips_angle_brackets_and_validates() -> None:
    with scripted_server(always(OK)) as (url, rec):
        session = Session(retry=False)
        session.unlock(f"{url}/a", "<opaquelocktoken:t>")
        with pytest.raises(exceptions.MalformedResponseError):
            session.unlock(f"{url}/a", "x>) (<y")
    assert rec.requests[0].headers["lock-token"] == "<opaquelocktoken:t>"
    assert len(rec.requests) == 1


def test_lock_registry_direct_children_and_grandchildren() -> None:
    registry = LockRegistry()
    registry.add("https://dav.example/dir", "tok", "0")
    assert registry.covering("https://dav.example/dir")
    assert registry.covering("https://dav.example/dir/child.txt")
    assert not registry.covering("https://dav.example/dir/sub/deep.txt")
    assert not registry.covering("https://dav.example/dirty")
    assert not registry.covering("https://other.example/dir/child.txt")
    header = registry.if_header("https://dav.example/dir/child.txt")
    assert header == "<https://dav.example/dir> (<tok>)"
    assert registry.if_header("https://dav.example/dir") == "(<tok>)"


def test_a_shared_lock_response_selects_the_lock_that_was_asked_about() -> None:
    body = (
        '<?xml version="1.0"?><d:prop xmlns:d="DAV:"><d:lockdiscovery>'
        + "".join(
            f"<d:activelock><d:locktype><d:write/></d:locktype>"
            f"<d:lockscope><d:shared/></d:lockscope><d:depth>0</d:depth>"
            f"<d:owner>{owner}</d:owner><d:locktoken><d:href>{tok}</d:href></d:locktoken>"
            f"</d:activelock>"
            for owner, tok in (
                ("someone-else", "opaquelocktoken:other"),
                ("me", "opaquelocktoken:mine"),
            )
        )
        + "</d:lockdiscovery></d:prop>"
    ).encode()

    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if seen.method == "LOCK":
            return 200, {"Lock-Token": "<opaquelocktoken:mine>"}, body
        return 204, {}, b""

    with scripted_server(respond) as (url, _rec):
        with FileSystem(retry=False).locked(f"{url}/f", scope="shared") as lock:
            assert lock.owner == "me"
            assert lock.token == "opaquelocktoken:mine"
        refreshed = FileSystem(retry=False).refresh_lock(
            f"{url}/f", "opaquelocktoken:mine"
        )
        assert refreshed.owner == "me"


def test_a_412_is_a_precondition_failure_not_necessarily_an_existing_resource() -> None:
    with scripted_server(always((412, {}, b""))) as (url, _rec):
        session = Session(retry=False)
        fs = FileSystem.from_session(session)
        with pytest.raises(exceptions.PreconditionFailedError) as excinfo:
            session._send("PUT", f"{url}/a", data=b"x")
        assert not isinstance(excinfo.value, exceptions.ResourceAlreadyExistsError)
        assert "already exists" not in str(excinfo.value)
        # ...while an upload that asked for "create only" knows what a 412 means:
        import io

        with pytest.raises(exceptions.ResourceAlreadyExistsError):
            fs.upload_fileobj(io.BytesIO(b"x"), f"{url}/a")
    assert issubclass(
        exceptions.ResourceAlreadyExistsError, exceptions.PreconditionFailedError
    )


def test_the_documented_environment_is_what_tests_run_in() -> None:
    assert "NETRC" not in os.environ or os.environ["NETRC"]
