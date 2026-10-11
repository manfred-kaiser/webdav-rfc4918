"""TLS state, redirect chains, credentials and origins: what the hardening of ``Session`` has to keep true.

Most tests here failed against the code before the hardening; the ones that
only pin what has to stay as it was say so in their names.
"""

# ruff: noqa: SIM117, PLC0415, S301, PT031, EM101
# (Nested servers in one ``with``, lazy imports and made-up secrets are the point of these tests.)

import base64
import contextlib
import copy
import logging
import pickle
import ssl
import threading
import traceback
import warnings
from collections.abc import Iterator
from http.server import HTTPServer
from pathlib import Path
from typing import Any

import pytest
import requests

from tests import previous_release_pickles as old
from tests.certificates import Certificates
from tests.scripted_server import (
    OK,
    Recorder,
    _make_handler,
    always,
    redirect,
    scripted_server,
)
from webdav import FileSystem, RedirectPolicy, Session, exceptions
from webdav.exceptions import ClientError, TLSConfigError
from webdav.transport.tls import TLSOptions

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def certs(tmp_path_factory: pytest.TempPathFactory) -> Certificates:
    return Certificates(tmp_path_factory.mktemp("ic-certs"))


@pytest.fixture(scope="module")
def other_ca(certs: Certificates) -> str:
    """The certificate file of a CA that signed nothing the servers here present."""
    return str(certs.issue_other_ca().with_suffix(".crt"))


class _QuietServer(HTTPServer):
    def handle_error(self, request: Any, client_address: Any) -> None:
        """A client that gives up the handshake is the point of some tests, not news."""


@contextlib.contextmanager
def tls_server(
    certs: Certificates, respond: Any, *, max_version: "ssl.TLSVersion | None" = None
) -> Iterator[tuple[str, Recorder]]:
    """A scripted server speaking TLS with the certificate of ``certs`` (valid for 127.0.0.1)."""
    recorder = Recorder()
    server = _QuietServer(("127.0.0.1", 0), _make_handler(respond, recorder))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certs.server_cert), str(certs.server_key))
    if max_version is not None:
        context.maximum_version = max_version
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"https://127.0.0.1:{server.server_address[1]}", recorder
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def _closed_port() -> int:
    import socket

    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


# ---------------------------------------------------------------------------
# A copy or a pickle keeps what was set after construction
# ---------------------------------------------------------------------------


def test_a_clone_keeps_a_verify_that_was_set_after_construction(
    certs: Certificates, other_ca: str
) -> None:
    with tls_server(certs, always(OK)) as (url, _rec):
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session = Session(verify=False, retry=False)
        session.verify = other_ca  # a CA that did not sign this server
        for clone in (copy.copy(session), pickle.loads(pickle.dumps(session))):
            assert clone.verify == other_ca
            with pytest.raises(requests.exceptions.SSLError):
                clone.get(f"{url}/x")


def test_a_clone_keeps_a_cert_that_was_set_after_construction(tmp_path: Path) -> None:
    cert, key = Certificates(tmp_path).issue_client_cert("client")
    session = Session()
    session.cert = (str(cert), str(key))
    for clone in (copy.copy(session), pickle.loads(pickle.dumps(session))):
        assert clone.cert == (str(cert), str(key))


def test_a_clone_with_tls_keeps_verify_and_cert_changes_too(
    certs: Certificates, other_ca: str
) -> None:
    with tls_server(certs, always(OK)) as (url, _rec):
        session = Session(verify=str(certs.ca_cert), tls=TLSOptions(), retry=False)
        assert session.get(f"{url}/x").status_code == 204
        session.verify = other_ca
        clone = copy.copy(session)
        assert clone.verify == other_ca
        with pytest.raises(requests.exceptions.SSLError):
            clone.get(f"{url}/x")


def test_pickles_of_the_previous_release_still_load() -> None:
    plain = pickle.loads(base64.b64decode("".join(old.PLAIN)))
    assert plain.base_url == "https://dav.example.org/base/"
    assert plain.auth == ("alice", "s3cret")
    assert plain.headers["X-Test"] == "1"
    assert plain.cookies.get("sid") == "abc"
    assert plain.verify is True
    # ... and the loaded session works like a new one.
    with scripted_server(always(OK)) as (url, rec):
        clone = pickle.loads(base64.b64decode("".join(old.PLAIN)))
        clone._base_url = None  # pytest-only: point it at the local server
        clone.get(f"{url}/x")
    assert rec.requests[0].headers["authorization"].startswith("Basic ")


def test_a_tls_session_pickle_of_the_previous_release_loads() -> None:
    session = pickle.loads(base64.b64decode("".join(old.TLS)))
    assert session.verify is True
    assert session.get_adapter("https://x").verifies  # type: ignore[attr-defined]


def test_a_filesystem_pickle_of_the_previous_release_loads() -> None:
    client = pickle.loads(base64.b64decode("".join(old.FILESYSTEM)))
    assert client.session.auth == ("bob", "pw")


# ---------------------------------------------------------------------------
# Setters rebuild a hardened adapter; the getter says what is in force
# ---------------------------------------------------------------------------


def test_verify_set_later_applies_with_tls(certs: Certificates, other_ca: str) -> None:
    with tls_server(certs, always(OK)) as (url, _rec):
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session = Session(verify=False, tls=TLSOptions(), retry=False)
            assert session.get(f"{url}/x").status_code == 204
        session.verify = other_ca
        assert session.verify == other_ca
        with pytest.raises(requests.exceptions.SSLError):
            session.get(f"{url}/x")
        session.verify = str(certs.ca_cert)
        assert session.get(f"{url}/x").status_code == 204
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session.verify = False
            assert session.get(f"{url}/x").status_code == 204


def test_the_verify_getter_of_a_tls_session_is_the_real_value(
    certs: Certificates,
) -> None:
    with pytest.warns(exceptions.TLSHardeningDisabledWarning):
        assert Session(verify=False, tls=TLSOptions()).verify is False
    assert Session(tls=TLSOptions()).verify is True
    assert Session(verify=str(certs.ca_cert), tls=TLSOptions()).verify == str(
        certs.ca_cert
    )


def test_verify_false_for_one_call_does_not_switch_a_verifying_tls_session_off(
    certs: Certificates, other_ca: str, caplog: pytest.LogCaptureFixture
) -> None:
    with tls_server(certs, always(OK)) as (url, _rec):
        session = Session(verify=other_ca, tls=TLSOptions(), retry=False)
        with warnings.catch_warnings():
            warnings.simplefilter("error")  # no "verification is off" - it is not
            with caplog.at_level(logging.WARNING, logger="webdav"):
                with pytest.raises(requests.exceptions.SSLError):
                    session.get(f"{url}/x", verify=False)
    assert any("ignored" in r.message for r in caplog.records)


def test_verify_true_for_one_call_is_refused_where_the_context_does_not_verify(
    certs: Certificates,
) -> None:
    with tls_server(certs, always(OK)) as (url, rec):
        with pytest.warns(exceptions.TLSHardeningDisabledWarning):
            session = Session(verify=False, tls=TLSOptions(), retry=False)
            with pytest.raises(ClientError, match=r"session\.verify"):
                session.get(f"{url}/x", verify=True)
            with pytest.raises(ClientError, match=r"session\.verify"):
                session.get(f"{url}/x", verify=str(certs.ca_cert))
            # per call None, and False (what the session does anyway), stay as they were
            assert session.get(f"{url}/x", verify=None).status_code == 204
            assert session.get(f"{url}/x", verify=False).status_code == 204
    assert len(rec.requests) == 2


def test_a_verify_that_cannot_be_applied_leaves_the_session_as_it_was(
    certs: Certificates, tmp_path: Path
) -> None:
    with tls_server(certs, always(OK)) as (url, _rec):
        session = Session(verify=str(certs.ca_cert), tls=TLSOptions(), retry=False)
        broken = tmp_path / "not-a-ca.pem"
        broken.write_text("this is not a certificate")
        with pytest.raises(TLSConfigError):
            session.verify = str(broken)
        assert session.verify == str(certs.ca_cert)
        assert session.get(f"{url}/x").status_code == 204


def test_changing_verify_while_other_threads_send_breaks_nothing(
    certs: Certificates,
) -> None:
    errors: list[BaseException] = []
    with tls_server(certs, always(OK)) as (url, _rec):
        session = Session(
            verify=str(certs.ca_cert),
            tls=TLSOptions(),
            retry=False,
            pool_maxsize=4,
        )
        stop = threading.Event()

        def sender() -> None:
            while not stop.is_set():
                try:
                    session.get(f"{url}/x")
                except requests.exceptions.RequestException:
                    pass  # a request that met a swap may fail; it must not crash
                except BaseException as exc:  # noqa: BLE001
                    errors.append(exc)

        threads = [threading.Thread(target=sender) for _ in range(3)]
        for thread in threads:
            thread.start()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for index in range(20):
                session.verify = str(certs.ca_cert) if index % 2 else False
        stop.set()
        for thread in threads:
            thread.join()
    assert errors == []


# ---------------------------------------------------------------------------
# verify is a bool or a path
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("verify", [None, 0, "", b"", 0.0, [], 1, object()])
def test_the_setter_refuses_what_is_no_bool_and_no_path(verify: object) -> None:
    session = Session()
    with pytest.raises(TypeError, match=r"True, False or the path"):
        session.verify = verify  # type: ignore[assignment]
    assert session.verify is True


def test_a_path_object_is_a_ca_bundle_without_and_with_tls(
    certs: Certificates, other_ca: str
) -> None:
    ca = certs.ca_cert
    with tls_server(certs, always(OK)) as (url, _rec):
        for tls in (None, TLSOptions()):
            session = Session(verify=ca, tls=tls, retry=False)
            assert session.get(f"{url}/x").status_code == 204
            assert session.verify == str(ca)
            # the private CA is the pin: it does not fall back to the system store
            wrong = Session(verify=Path(other_ca), tls=tls, retry=False)
            with pytest.raises(requests.exceptions.SSLError):
                wrong.get(f"{url}/x")


def test_a_falsy_verify_in_an_old_pickle_stays_what_it_meant() -> None:
    """The pickled session ran unverified (loudly); loading it must not turn that into an error or into verification."""
    with pytest.warns(exceptions.TLSHardeningDisabledWarning):
        session = pickle.loads(base64.b64decode("".join(old.FALSY_VERIFY)))
    assert session.verify is False


def test_a_refused_verify_leaves_the_session_as_it_was(certs: Certificates) -> None:
    with tls_server(certs, always(OK)) as (url, _rec):
        session = Session(verify=str(certs.ca_cert), tls=TLSOptions(), retry=False)
        with pytest.raises(TypeError):
            session.verify = ""  # type: ignore[assignment]
        assert session.verify == str(certs.ca_cert)
        assert session.get(f"{url}/x").status_code == 204


def test_verify_none_for_one_call_means_the_sessions_own() -> None:
    with scripted_server(always(OK)) as (url, rec):
        Session(retry=False).get(f"{url}/x", verify=None)
    assert len(rec.requests) == 1


# ---------------------------------------------------------------------------
# The query of a signed URL is not in a transport error
# ---------------------------------------------------------------------------

_SIGNATURE = "SECRETSIG-0123"


def _whole(exc: BaseException) -> str:
    return "".join(traceback.format_exception(exc)) + repr(exc.args)


def test_a_connection_error_after_a_redirect_does_not_show_the_signed_query() -> None:
    target = f"http://127.0.0.1:{_closed_port()}/dl/file?X-Amz-Signature={_SIGNATURE}&token=TOK"
    with scripted_server(lambda _r: redirect(302, target)) as (url, _rec):
        session = Session(redirect_policy=RedirectPolicy.ALL, retry=False)
        with pytest.raises(requests.exceptions.ConnectionError) as caught:
            session.get(f"{url}/x")
    assert _SIGNATURE not in _whole(caught.value)
    assert "TOK" not in str(caught.value)
    assert "<redacted>" in str(caught.value)


def test_a_connection_error_for_the_callers_own_query_does_not_show_it() -> None:
    url = f"http://127.0.0.1:{_closed_port()}/dl?sig={_SIGNATURE}"
    with pytest.raises(requests.exceptions.ConnectionError) as caught:
        Session(retry=False).get(url)
    assert _SIGNATURE not in _whole(caught.value)


def test_the_cause_chain_is_cleaned_in_place_not_cut() -> None:
    import urllib3.exceptions

    url = f"http://127.0.0.1:{_closed_port()}/dl?sig={_SIGNATURE}"
    with pytest.raises(requests.exceptions.ConnectionError) as caught:
        Session(retry=False).get(url)
    inner = caught.value.args[0]
    assert isinstance(inner, urllib3.exceptions.MaxRetryError)
    assert isinstance(inner.reason, urllib3.exceptions.NewConnectionError)
    assert caught.value.request is not None
    assert caught.value.__cause__ is None or isinstance(
        caught.value.__cause__, BaseException
    )


def test_a_failed_unlock_logs_no_query(caplog: pytest.LogCaptureFixture) -> None:
    client = FileSystem(retry=False)
    with caplog.at_level(logging.WARNING, logger="webdav"):
        client._unlock_quietly(
            f"http://127.0.0.1:{_closed_port()}/a?sig={_SIGNATURE}",
            "opaquelocktoken:1",
        )
    assert caplog.records
    assert _SIGNATURE not in caplog.text


# ---------------------------------------------------------------------------
# No netrc behind an auth that is falsy
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("falsy", [False, (), ""])
def test_a_falsy_auth_does_not_read_netrc(
    falsy: object, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    netrc = tmp_path / "netrc"
    netrc.write_text("machine 127.0.0.1 login netrcuser password netrcpass\n")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    monkeypatch.setenv("HOME", str(tmp_path))
    with scripted_server(always(OK)) as (url, rec):
        Session(retry=False).get(f"{url}/a", auth=falsy)
        Session(retry=False).propfind(f"{url}/a", depth=0, auth=falsy)
        Session(auth=falsy, retry=False).get(f"{url}/a")  # type: ignore[arg-type]
    assert len(rec.requests) == 3
    assert all("authorization" not in r.headers for r in rec.requests)


def test_a_per_call_false_auth_still_beats_the_sessions() -> None:
    with scripted_server(always(OK)) as (url, rec):
        Session(auth=("u", "p"), retry=False).get(f"{url}/a", auth=False)
        Session(auth=("u", "p"), retry=False).get(f"{url}/a")
    assert "authorization" not in rec.requests[0].headers
    assert rec.requests[1].headers["authorization"].startswith("Basic ")


# ---------------------------------------------------------------------------
# Cookies
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("host", "cookie", "kept"),
    [
        ("127.0.0.1", "a=b; Domain=.0.1", 0),  # an IP address has no sibling hosts
        ("127.0.0.1", "a=b; Domain=1", 0),
        ("127.0.0.1", "a=b; Domain=127.0.0.1", 1),  # the address itself is fine
        ("10.0.0.5", "a=b; Domain=10.0.0.5", 1),
        ("127.0.0.1", "a=b", 1),
        ("dav.example.com", "a=b; Domain=.example.com", 1),  # names keep Domain cookies
        ("dav.example.com", "a=b; Domain=example.com", 1),
        ("dav.example.com", "a=b", 1),
    ],
)
def test_cookie_domain_rules(host: str, cookie: str, kept: int) -> None:
    session = Session()
    assert _accepted(host, session.cookies, cookie) == kept


def test_a_planted_cookie_is_not_sent_to_a_neighbour_address() -> None:
    session = Session()
    _accepted("127.0.0.1", session.cookies, "planted=1; Domain=.0.1")
    from requests.cookies import get_cookie_header

    request = requests.Request("GET", "http://127.1.0.1/").prepare()
    assert get_cookie_header(session.cookies, request) is None  # type: ignore[no-untyped-call]


def test_cookie_size_limits() -> None:
    session = Session()
    limit = jar_policy.MAX_COOKIE_SIZE
    assert _accepted("h.example", session.cookies, "a=" + "x" * (limit - 1)) == 1
    assert (
        _accepted("h.example", session.cookies, "b=" + "x" * limit) == 1
    )  # too large: not kept


def test_a_large_sso_cookie_of_ten_kib_is_kept() -> None:
    session = Session()
    assert _accepted("h.example", session.cookies, "sso=" + "x" * 10_000) == 1


def test_one_domain_cannot_hold_more_than_the_limit_but_a_cookie_can_be_replaced() -> (
    None
):
    session = Session()
    for index in range(jar_policy.MAX_COOKIES_PER_DOMAIN + 20):
        _accepted("h.example", session.cookies, f"c{index}=1")
    assert len(session.cookies) == jar_policy.MAX_COOKIES_PER_DOMAIN
    _accepted("h.example", session.cookies, "c0=new")
    assert session.cookies.get("c0") == "new"
    assert len(session.cookies) == jar_policy.MAX_COOKIES_PER_DOMAIN
    _accepted(
        "other.example", session.cookies, "x=1"
    )  # another domain has its own room
    assert len(session.cookies) == jar_policy.MAX_COOKIES_PER_DOMAIN + 1


def test_the_whole_jar_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(jar_policy, "MAX_JAR_SIZE", 5000)
    session = Session()
    for index in range(10):
        _accepted(f"h{index}.example", session.cookies, "a=" + "x" * 1000)
    assert 1 <= len(session.cookies) <= 5


def test_a_hundred_big_cookies_per_response_do_not_fill_the_jar() -> None:
    session = Session()
    cookies = [f"c{i}=" + "x" * 15_000 for i in range(100)]
    _accepted("h.example", session.cookies, *cookies)
    held = sum(len(c.name) + len(c.value or "") for c in session.cookies)
    assert held <= jar_policy.MAX_JAR_SIZE


def test_cookies_set_by_hand_are_not_cut() -> None:
    session = Session()
    session.cookies.set("big", "x" * 100_000, domain="h.example")
    assert len(session.cookies) == 1


def test_a_copy_has_the_policy_and_a_jar_of_the_callers_own_stays_theirs() -> None:
    guarded = copy.copy(Session())
    assert _accepted("127.0.0.1", guarded.cookies, "a=b; Domain=.0.1") == 0
    own = Session()
    own.cookies = RequestsCookieJar()
    clone = copy.copy(own)
    assert _accepted("127.0.0.1", clone.cookies, "a=b; Domain=.0.1") == 1


def test_a_new_pickle_needs_nothing_a_plain_requests_jar_cannot_load() -> None:
    session = Session("https://dav.example.org")
    session.cookies.set("sid", "abc", domain="dav.example.org")
    data = pickle.dumps(session)
    assert b"transport.cookies" not in data
    assert b"_Policy" not in data
    loaded = pickle.loads(data)
    assert type(loaded.cookies) is RequestsCookieJar
    assert loaded.cookies.get("sid") == "abc"


def test_a_server_cannot_plant_a_cookie_end_to_end() -> None:
    with scripted_server(
        always((204, {"Set-Cookie": "planted=1; Domain=.0.1"}, b""))
    ) as (url, _rec):
        session = Session(retry=False)
        session.get(f"{url}/x")
    assert len(session.cookies) == 0


def test_a_normal_cookie_session_still_works_end_to_end() -> None:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if "cookie" not in seen.headers:
            return 204, {"Set-Cookie": "sid=abc; Path=/"}, b""
        return OK

    with scripted_server(respond) as (url, rec):
        session = Session(retry=False)
        session.get(f"{url}/login")
        session.get(f"{url}/next")
    assert rec.requests[1].headers["cookie"] == "sid=abc"


# ---------------------------------------------------------------------------
# A copy shares no containers with its original
# ---------------------------------------------------------------------------


def test_a_copy_does_not_share_its_containers() -> None:
    session = Session(headers={"X-A": "1"})
    session.params = {"a": "1"}
    session.proxies = {"http": "http://proxy.example:3128"}
    session.cookies.set("c", "1", domain="h.example")
    clone = copy.copy(session)
    clone.headers["X-B"] = "2"
    clone.params["b"] = "2"
    clone.proxies["https"] = "http://other.example:3128"
    clone.cookies.set("d", "2", domain="h.example")
    clone.hooks["response"].append(lambda r, **_k: r)
    assert "X-B" not in session.headers
    assert session.params == {"a": "1"}
    assert "https" not in session.proxies
    assert session.cookies.get("d") is None
    assert session.hooks["response"] == []
    assert clone.headers["X-A"] == "1"
    assert clone.cookies.get("c") == "1"


def test_a_pickle_roundtrip_is_unchanged() -> None:
    session = Session("https://h.example", auth=("u", "p"), headers={"X-A": "1"})
    clone = pickle.loads(pickle.dumps(session))
    assert clone.auth == ("u", "p")
    assert clone.headers["X-A"] == "1"


# ---------------------------------------------------------------------------
# send() refuses what request() refuses
# ---------------------------------------------------------------------------


def test_send_refuses_another_origin_than_the_base_url() -> None:
    with scripted_server(always(OK)) as (other, other_rec):
        with scripted_server(always(OK)) as (url, rec):
            session = Session(
                url, auth=("u", "p"), headers={"X-Api-Key": "K"}, retry=False
            )
            prepared = session.prepare_request(requests.Request("GET", f"{other}/x"))
            assert prepared.headers[
                "Authorization"
            ]  # prepare_request prepares as asked
            with pytest.raises(ClientError, match="base_url"):
                session.send(prepared)
            ok = session.prepare_request(requests.Request("GET", f"{url}/y"))
            assert session.send(ok).status_code == 204
    assert other_rec.requests == []
    assert len(rec.requests) == 1


def test_send_refuses_a_url_with_credentials_in_it() -> None:
    with scripted_server(always(OK)) as (url, rec):
        host = url.removeprefix("http://")
        session = Session(retry=False)
        prepared = session.prepare_request(
            requests.Request("GET", f"http://u:p@{host}/x")
        )
        with pytest.raises(ClientError, match="credentials"):
            session.send(prepared)
    assert rec.requests == []


def test_send_without_a_base_url_still_sends_to_any_http_url() -> None:
    with scripted_server(always(OK)) as (url, _rec):
        session = Session(retry=False)
        assert (
            session.send(
                session.prepare_request(requests.Request("GET", f"{url}/x"))
            ).status_code
            == 204
        )


# ---------------------------------------------------------------------------
# trust_env
# ---------------------------------------------------------------------------


def test_trust_env_false_ignores_the_environment_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with scripted_server(always(OK)) as (proxy, proxy_rec):
        monkeypatch.setenv("HTTP_PROXY", proxy)
        monkeypatch.setenv("http_proxy", proxy)
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        Session(retry=False).get(
            "http://dav.invalid/x"
        )  # the default: through the proxy
        assert len(proxy_rec.requests) == 1
        with pytest.raises(requests.exceptions.ConnectionError):
            Session(retry=False, trust_env=False, timeout=(0.5, 0.5)).get(
                "http://dav.invalid/x"
            )
        assert len(proxy_rec.requests) == 1


def test_trust_env_is_a_bool_and_an_option_everywhere() -> None:
    with pytest.raises(TypeError):
        Session(trust_env=0)  # type: ignore[arg-type]
    assert Session().trust_env is True
    assert FileSystem("http://dav.example", trust_env=False).session.trust_env is False
    assert pickle.loads(pickle.dumps(Session(trust_env=False))).trust_env is False


def test_a_connection_error_through_an_environment_proxy_says_so(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    dead = f"http://proxyuser:proxypw@127.0.0.1:{_closed_port()}"
    monkeypatch.setenv("HTTP_PROXY", dead)
    monkeypatch.setenv("http_proxy", dead)
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    with caplog.at_level(logging.WARNING, logger="webdav"):
        with pytest.raises(requests.exceptions.ConnectionError) as caught:
            Session(retry=False).get("http://dav.invalid/x")
    notes = " ".join(getattr(caught.value, "__notes__", []))
    assert "trust_env=False" in notes
    assert "trust_env=False" in caplog.text
    assert "proxypw" not in notes + caplog.text


# ---------------------------------------------------------------------------
# A Digest challenge that cannot be used
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "challenge", ['Digest nonce="n"', 'Digest realm="r"', "Digest"]
)
def test_a_broken_digest_challenge_is_a_client_error_with_its_cause(
    challenge: str,
) -> None:
    with scripted_server(always((401, {"WWW-Authenticate": challenge}, b""))) as (
        url,
        _rec,
    ):
        session = Session(auth=HTTPDigestAuth("u", "p"), retry=False)
        with pytest.raises(ClientError, match="Digest") as caught:
            session.get(f"{url}/x")
    assert isinstance(caught.value.__cause__, KeyError)


def test_a_valid_digest_handshake_still_works() -> None:
    def respond(seen: Seen) -> tuple[int, dict[str, str], bytes]:
        if "authorization" not in seen.headers:
            return (
                401,
                {"WWW-Authenticate": 'Digest realm="r", nonce="abc", qop="auth"'},
                b"",
            )
        return OK

    with scripted_server(respond) as (url, rec):
        response = Session(auth=HTTPDigestAuth("u", "p"), retry=False).get(f"{url}/x")
    assert response.status_code == 204
    assert rec.requests[1].headers["authorization"].startswith("Digest ")


def test_a_failing_hook_of_the_callers_is_not_turned_into_a_client_error() -> None:
    def boom(_response: Any, **_kwargs: Any) -> None:
        raise KeyError("mine")

    with scripted_server(
        always((401, {"WWW-Authenticate": 'Basic realm="r"'}, b""))
    ) as (url, _rec):
        with pytest.raises(KeyError):
            Session(retry=False).get(f"{url}/x", hooks={"response": boom})
