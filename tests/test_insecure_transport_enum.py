"""``insecure_transport`` is an ``InsecureTransport``; the refusal cites RFC 4918 section 20.1 for Basic."""

import copy
import pickle
from typing import Any

import pytest
from requests.auth import HTTPBasicAuth

from webdav import BasicAuth, ClientError, InsecureTransport, Session
from webdav.exceptions import InsecureTransportWarning

REMOTE = "http://192.0.2.1:9/x"  # TEST-NET: never answers; the decision comes before a connection
QUICK: dict[str, Any] = {"retry": False, "timeout": (0.05, 0.05)}


def test_the_members_are_strings() -> None:
    assert InsecureTransport.ERROR == "error"
    assert InsecureTransport("warn") is InsecureTransport.WARN
    assert [mode.value for mode in InsecureTransport] == ["error", "warn", "allow"]


def test_the_default_is_error_and_a_string_is_turned_into_the_member() -> None:
    assert Session().insecure_transport is InsecureTransport.ERROR
    assert (
        Session(insecure_transport="warn").insecure_transport is InsecureTransport.WARN
    )
    assert (
        Session(insecure_transport=InsecureTransport.ALLOW).insecure_transport
        is InsecureTransport.ALLOW
    )
    session = Session()
    session.insecure_transport = "allow"
    assert session.insecure_transport is InsecureTransport.ALLOW


@pytest.mark.parametrize("value", ["WARN", "yes", "", None, True, 1, b"warn"])
def test_anything_else_is_a_value_error(value: object) -> None:
    with pytest.raises(ValueError, match="insecure_transport must be"):
        Session(insecure_transport=value)  # type: ignore[arg-type]


def test_the_mode_survives_a_pickle_and_a_copy() -> None:
    session = Session(insecure_transport=InsecureTransport.WARN)
    assert (
        pickle.loads(pickle.dumps(session)).insecure_transport is InsecureTransport.WARN
    )
    assert copy.copy(session).insecure_transport is InsecureTransport.WARN


@pytest.mark.parametrize(
    "auth",
    [("user", "secret"), HTTPBasicAuth("user", "secret"), BasicAuth("user", "secret")],
)
def test_the_refusal_of_basic_cites_the_rfc(auth: object) -> None:
    with pytest.raises(ClientError) as caught:
        Session(auth=auth, **QUICK).get(REMOTE)  # type: ignore[arg-type]
    text = str(caught.value)
    assert "RFC 4918 section 20.1" in text
    assert (
        "Basic authentication MUST NOT be used unless the connection is secure" in text
    )
    assert "InsecureTransport.WARN" in text
    assert "--allow-insecure" in text
    assert "secret" not in text


def test_an_authorization_basic_header_counts_as_basic() -> None:
    with pytest.raises(ClientError, match="RFC 4918 section 20.1"):
        Session(**QUICK).get(REMOTE, headers={"Authorization": "Basic dXNlcjpwdw=="})


@pytest.mark.parametrize(
    "headers", [{"Authorization": "Bearer token"}, {"Cookie": "sid=1"}]
)
def test_the_refusal_of_other_credentials_does_not_claim_the_rfc_forbids_them(
    headers: dict[str, str],
) -> None:
    with pytest.raises(ClientError) as caught:
        Session(**QUICK).get(REMOTE, headers=headers)
    assert "RFC 4918" not in str(caught.value)
    assert "anyone on the network path can read them" in str(caught.value)


@pytest.mark.parametrize("mode", ["warn", InsecureTransport.WARN])
def test_the_warning_for_basic_cites_the_rfc(mode: object) -> None:
    session = Session(auth=("user", "secret"), insecure_transport=mode, **QUICK)  # type: ignore[arg-type]
    with pytest.warns(InsecureTransportWarning, match="RFC 4918 section 20.1"):
        with pytest.raises(Exception, match=r"192\.0\.2\.1"):
            session.get(REMOTE)
