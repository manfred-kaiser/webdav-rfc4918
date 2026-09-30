"""``webdav.<name>`` and the matching ``Session``/``FileSystem`` method are the same function.

Every module-level name is defined by exactly one of the two - never both, see
``webdav.fs`` for why (``copy``/``move`` collide by name between the verb and
the file-system operation, so only one of each pair gets a module function).
"""

import inspect
from typing import Any, get_type_hints

import pytest

import webdav
from webdav import FileSystem, Session

_FUNCTIONS = sorted(
    name
    for name in webdav.__all__
    if callable(getattr(webdav, name)) and not isinstance(getattr(webdav, name), type)
)


#: Defined on both classes with different meanings (the verb vs. the
#: file-system operation) - only the ``FileSystem`` one gets a module
#: function, see ``webdav.fs``.
_FS_EVEN_THOUGH_ALSO_A_VERB = {"copy", "move"}


def _owner(name: str) -> type:
    """Whichever of ``Session``/``FileSystem`` the module function ``name`` mirrors."""
    if name in _FS_EVEN_THOUGH_ALSO_A_VERB:
        return FileSystem
    return Session if hasattr(Session, name) else FileSystem


def _parameters(function: Any, *, drop_self: bool) -> "list[tuple[str, Any, Any]]":
    parameters = list(inspect.signature(function).parameters.values())
    if drop_self:
        parameters = parameters[1:]
    return [
        (p.name, p.kind, p.default) for p in parameters if p.kind is not p.VAR_KEYWORD
    ]


@pytest.mark.parametrize("name", _FUNCTIONS)
def test_module_function_and_method_have_the_same_parameters(name: str) -> None:
    function, method = getattr(webdav, name), getattr(_owner(name), name)
    assert _parameters(function, drop_self=False) == _parameters(method, drop_self=True)


@pytest.mark.parametrize("name", _FUNCTIONS)
def test_module_function_and_method_return_the_same_type(name: str) -> None:
    if name in {"open", "locked", "request"}:
        pytest.skip("context managers / overloads are compared by parameters only")
    function, method = getattr(webdav, name), getattr(_owner(name), name)
    assert str(inspect.signature(function).return_annotation) == str(
        inspect.signature(method).return_annotation
    ) or get_type_hints(function).get("return") == get_type_hints(method).get("return")


@pytest.mark.parametrize("name", _FUNCTIONS)
def test_every_module_function_is_a_session_or_filesystem_method(name: str) -> None:
    assert hasattr(Session, name) or hasattr(FileSystem, name)
