"""``webdav.<name>`` and ``Session.<name>`` are the same function: same parameters, same result."""

import inspect
from typing import Any, get_type_hints

import pytest

import webdav
from webdav import Session

_FUNCTIONS = sorted(
    name
    for name in webdav.__all__
    if callable(getattr(webdav, name)) and not isinstance(getattr(webdav, name), type)
)
#: What only a module-level function has (there is no session to configure).
_OPTIONS = {"options", "kwargs"}


def _parameters(function: Any, *, drop_self: bool) -> "list[tuple[str, Any, Any]]":
    parameters = list(inspect.signature(function).parameters.values())
    if drop_self:
        parameters = parameters[1:]
    return [
        (p.name, p.kind, p.default) for p in parameters if p.kind is not p.VAR_KEYWORD
    ]


@pytest.mark.parametrize("name", _FUNCTIONS)
def test_module_function_and_session_method_have_the_same_parameters(name: str) -> None:
    function, method = getattr(webdav, name), getattr(Session, name)
    assert _parameters(function, drop_self=False) == _parameters(method, drop_self=True)


@pytest.mark.parametrize("name", _FUNCTIONS)
def test_module_function_and_session_method_return_the_same_type(name: str) -> None:
    if name in {"open", "locked", "request"}:
        pytest.skip("context managers / overloads are compared by parameters only")
    function, method = getattr(webdav, name), getattr(Session, name)
    assert str(inspect.signature(function).return_annotation) == str(
        inspect.signature(method).return_annotation
    ) or get_type_hints(function).get("return") == get_type_hints(method).get("return")


@pytest.mark.parametrize("name", _FUNCTIONS)
def test_every_module_function_is_a_session_method(name: str) -> None:
    assert hasattr(Session, name)
