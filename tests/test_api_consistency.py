"""``webdav.<name>`` and the matching ``FileSystem`` method are the same function.

``Session`` has no module-level one-off mirror (see ``webdav.fs.api``'s
docstring for why) - only ``webdav.fs``'s file-system-shaped functions are
checked here.
"""

import inspect
from typing import Any, get_type_hints

import pytest

import webdav
from webdav import FileSystem

_FUNCTIONS = sorted(
    name
    for name in webdav.__all__
    if callable(getattr(webdav, name)) and not isinstance(getattr(webdav, name), type)
)


def _parameters(function: Any, *, drop_self: bool) -> "list[tuple[str, Any, Any]]":
    parameters = list(inspect.signature(function).parameters.values())
    if drop_self:
        parameters = parameters[1:]
    return [
        (p.name, p.kind, p.default) for p in parameters if p.kind is not p.VAR_KEYWORD
    ]


@pytest.mark.parametrize("name", _FUNCTIONS)
def test_module_function_and_method_have_the_same_parameters(name: str) -> None:
    function, method = getattr(webdav, name), getattr(FileSystem, name)
    assert _parameters(function, drop_self=False) == _parameters(method, drop_self=True)


@pytest.mark.parametrize("name", _FUNCTIONS)
def test_module_function_and_method_return_the_same_type(name: str) -> None:
    if name in {"open", "locked"}:
        pytest.skip("context managers / overloads are compared by parameters only")
    function, method = getattr(webdav, name), getattr(FileSystem, name)
    assert str(inspect.signature(function).return_annotation) == str(
        inspect.signature(method).return_annotation
    ) or get_type_hints(function).get("return") == get_type_hints(method).get("return")


@pytest.mark.parametrize("name", _FUNCTIONS)
def test_every_module_function_is_a_filesystem_method(name: str) -> None:
    assert hasattr(FileSystem, name)


def test_the_options_of_every_entry_point_are_those_of_session() -> None:
    """One list of options: ``Session(...)``, ``FileSystem(...)`` and the one-off functions."""
    from webdav.session import (
        ConnectionOptions,
        Session,
        SessionOptions,
    )  # noqa: PLC0415

    parameters = set(inspect.signature(Session.__init__).parameters)
    keyword_only = {
        name
        for name, p in inspect.signature(Session.__init__).parameters.items()
        if p.kind is p.KEYWORD_ONLY
    }
    assert parameters - keyword_only == {"self", "base_url"}
    assert set(SessionOptions.__annotations__) == keyword_only
    assert set(ConnectionOptions.__annotations__) == keyword_only - {
        "headers",
        "chunk_size",
    }


def test_a_filesystem_hands_out_its_session() -> None:
    from webdav import FileSystem, Session  # noqa: PLC0415

    own = FileSystem("http://dav.example")
    assert isinstance(own.session, Session)
    shared = Session("http://dav.example")
    assert FileSystem.from_session(shared).session is shared
