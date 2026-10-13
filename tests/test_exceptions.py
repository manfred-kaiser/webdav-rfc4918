"""The exception hierarchy: introspection, pickling, copying and what an error carries."""

import copy
import inspect
import pickle
from concurrent.futures import ProcessPoolExecutor
from io import BytesIO
from multiprocessing import get_context
from typing import Any

import pytest
import requests
from requests.structures import CaseInsensitiveDict

import webdav.exceptions as exceptions_module
from webdav import Response
from webdav.exceptions import (
    HTTPStatusError,
    MultiStatusError,
    ResourceLockedError,
    ResourceNotFoundError,
    WebDAVError,
)


def make_response(
    status: int = 200,
    body: bytes = b"",
    *,
    method: str = "PUT",
    url: str = "http://dav.example/f",
    headers: "dict[str, str] | None" = None,
    request_headers: "dict[str, str] | None" = None,
    reason: "str | None" = None,
) -> Response:
    """A fully read :class:`~webdav.Response` for ``method`` on ``url``."""
    response = Response()
    response.status_code = status
    response.url = url
    response.reason = reason  # type: ignore[assignment]
    response.headers.update(headers or {})
    response._content = body
    response._content_consumed = True  # type: ignore[attr-defined]
    request = requests.PreparedRequest()
    request.method = method
    request.url = url
    request.headers = CaseInsensitiveDict(request_headers or {})
    response.request = request
    return response


def _every_exception() -> "list[WebDAVError]":
    body = b'<d:error xmlns:d="DAV:"><d:lock-token-submitted/></d:error>'
    found: list[WebDAVError] = []
    for _name, cls in inspect.getmembers(exceptions_module, inspect.isclass):
        if not issubclass(cls, WebDAVError) or cls.__module__.split(".")[0] != "webdav":
            continue
        if issubclass(cls, HTTPStatusError):
            found.append(cls(make_response(409, body, reason="Conflict"), path="/p"))
        elif cls is MultiStatusError:
            found.append(
                MultiStatusError(
                    {"/a": "Locked", "/b": "Not Found"},
                    error_codes={"/a": frozenset({"no-conflicting-lock"})},
                )
            )
        elif cls.__name__ in ("IsACollectionError", "IsAResourceError"):
            found.append(cls("/p", "more"))
        else:
            found.append(cls("some message"))
    return found


EXCEPTIONS = _every_exception()


def test_exc02_the_introspection_found_the_whole_hierarchy() -> None:
    assert len(EXCEPTIONS) >= 20
    assert {type(e).__name__ for e in EXCEPTIONS} >= {
        "ResourceNotFoundError",
        "ResourceLockedError",
        "MultiStatusError",
        "RedirectNotFollowedError",
        "ClientError",
    }


def _same(a: WebDAVError, b: WebDAVError) -> None:
    assert type(a) is type(b)
    assert str(a) == str(b)
    if isinstance(a, HTTPStatusError | MultiStatusError):
        assert a.args == b.args
    for attr in ("path", "statuses", "error_codes", "status_code", "msg"):
        assert getattr(a, attr, None) == getattr(b, attr, None), attr
    if isinstance(a, HTTPStatusError):
        assert isinstance(b, HTTPStatusError)
        assert a.response.status_code == b.response.status_code
        assert a.response.headers == b.response.headers
        assert a.response.request.method == b.response.request.method


@pytest.mark.parametrize("exc", EXCEPTIONS, ids=lambda e: type(e).__name__)
@pytest.mark.parametrize(
    "roundtrip",
    [
        lambda e: pickle.loads(pickle.dumps(e)),
        copy.copy,
        copy.deepcopy,
    ],
    ids=["pickle", "copy", "deepcopy"],
)
def test_exc02_every_exception_survives_pickle_and_copy(
    exc: WebDAVError, roundtrip: Any
) -> None:
    _same(exc, roundtrip(exc))


def test_exc02_the_message_of_a_multi_status_error_is_not_doubled() -> None:
    exc = MultiStatusError({"/a": "Locked", "/b": "Not Found"})
    assert str(pickle.loads(pickle.dumps(exc))) == str(exc)


class _PickleOfRelease12:
    """What 1.2 wrote for a ``MultiStatusError``: the class, the message, the attributes."""

    def __reduce__(self) -> Any:
        message = "multiple errors received: {'/a': 'Locked', '/b': 'Not Found'}"
        state = {
            "response": None,
            "request": None,
            "statuses": {"/a": "Locked", "/b": "Not Found"},
            "error_codes": {},
            "msg": message,
        }
        return MultiStatusError, (message,), state


def test_exc02_a_pickle_made_by_release_1_2_still_loads() -> None:
    exc = pickle.loads(pickle.dumps(_PickleOfRelease12()))
    assert isinstance(exc, MultiStatusError)
    assert exc.statuses == {"/a": "Locked", "/b": "Not Found"}
    assert str(exc) == "multiple errors received: {'/a': 'Locked', '/b': 'Not Found'}"


def test_exc02_the_error_codes_of_a_read_body_survive() -> None:
    exc = next(e for e in EXCEPTIONS if isinstance(e, ResourceLockedError))
    assert exc.error_codes == {"lock-token-submitted"}
    assert pickle.loads(pickle.dumps(exc)).error_codes == {"lock-token-submitted"}


def test_exc02_an_unread_stream_is_never_read_by_pickling() -> None:
    raw = BytesIO(b"x" * 1000)
    response = make_response(404)
    response._content = False  # type: ignore[assignment]
    response._content_consumed = False  # type: ignore[attr-defined]
    response.raw = raw
    exc = ResourceNotFoundError(response, path="/p")
    revived = pickle.loads(pickle.dumps(exc))
    assert raw.tell() == 0
    assert revived.response.content == b""


def test_exc02_the_snapshot_body_is_capped() -> None:
    exc = ResourceNotFoundError(make_response(404, b"y" * 500_000), path="/p")
    assert len(pickle.loads(pickle.dumps(exc)).response.content) <= 64 * 1024


def test_exc02_the_snapshot_carries_no_credentials() -> None:
    response = make_response(404, request_headers={"Authorization": "Basic c2VjcmV0"})
    revived = pickle.loads(pickle.dumps(ResourceNotFoundError(response, path="/p")))
    assert b"c2VjcmV0" not in pickle.dumps(revived)
    assert revived.response.request.headers["Authorization"] == "[redacted]"


def _raise_not_found() -> None:
    raise ResourceNotFoundError(make_response(404), path="/worker")


def test_exc02_an_error_crosses_a_process_pool() -> None:
    with ProcessPoolExecutor(max_workers=1, mp_context=get_context("spawn")) as pool:
        with pytest.raises(ResourceNotFoundError, match="/worker"):
            pool.submit(_raise_not_found).result(timeout=60)
