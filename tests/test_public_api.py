"""The public surface is pinned: a refactoring must not add, drop or reshape it by accident.

``tests/test_api_consistency.py`` compares ``webdav.fs``'s functions with
``FileSystem``'s methods; this file pins what ``Session`` and the package
namespaces expose. Changing the public API on purpose means changing the
expectations here in the same commit.
"""

import inspect

import webdav
import webdav.fs
import webdav.session
from webdav import Session

_PACKAGE_ALL = [
    "ClientError",
    "FileSystem",
    "ForbiddenError",
    "HTTPStatusError",
    "InsufficientStorageError",
    "IsACollectionError",
    "IsAResourceError",
    "LockError",
    "MalformedResponseError",
    "MultiStatusError",
    "RedirectNotFollowedError",
    "RedirectPolicy",
    "Resource",
    "ResourceAlreadyExistsError",
    "ResourceConflictError",
    "ResourceLockedError",
    "ResourceNotFoundError",
    "Response",
    "Session",
    "TLSConfigError",
    "WebDAVError",
    "__version__",
    "content_language",
    "content_length",
    "content_type",
    "copy",
    "created",
    "dav_compliance",
    "download_file",
    "download_fileobj",
    "etag",
    "exists",
    "get_props",
    "info",
    "isdir",
    "isfile",
    "locked",
    "ls",
    "mkdir",
    "modified",
    "move",
    "open",
    "refresh_lock",
    "remove",
    "set_props",
    "upload_file",
    "upload_fileobj",
    "walk",
]

_FS_ALL = [
    "FileSystem",
    "content_language",
    "content_length",
    "content_type",
    "copy",
    "created",
    "dav_compliance",
    "download_file",
    "download_fileobj",
    "etag",
    "exists",
    "get_props",
    "info",
    "isdir",
    "isfile",
    "locked",
    "ls",
    "mkdir",
    "modified",
    "move",
    "open",
    "refresh_lock",
    "remove",
    "set_props",
    "upload_file",
    "upload_fileobj",
    "walk",
]

_SESSION_ALL = ["DEFAULT_MAX_RESPONSE_SIZE", "DEFAULT_TIMEOUT", "Method", "Session"]

#: Attributes ``Session()`` carries on the instance.
_SESSION_INSTANCE_ATTRIBUTES = [
    "base_url",
    "locks",
    "raise_on_error",
    "redirect_policy",
    "timeout",
    "with_retry",
]

#: The properties ``Session`` forwards to (or derives from) its transport.
_SESSION_PROPERTIES = [
    "auth",
    "cert",
    "chunk_size",
    "cookies",
    "headers",
    "hooks",
    "max_redirects",
    "max_response_size",
    "max_response_time",
    "params",
    "proxies",
    "redirect_forward_headers",
    "stream",
    "trust_env",
    "verify",
]

#: Public methods: ``name (parameter:KIND=default, ...)`` - annotations are left
#: out on purpose, they are spelled differently across Python versions.
_SESSION_METHODS = {
    "close": "(self:POSITIONAL_OR_KEYWORD)",
    "copy": "(self:POSITIONAL_OR_KEYWORD, url:POSITIONAL_OR_KEYWORD, destination:POSITIONAL_OR_KEYWORD, overwrite:KEYWORD_ONLY=False, depth:KEYWORD_ONLY=None, kwargs:VAR_KEYWORD)",
    "delete": "(self:POSITIONAL_OR_KEYWORD, url:POSITIONAL_OR_KEYWORD, if_match:KEYWORD_ONLY=None, kwargs:VAR_KEYWORD)",
    "features_for": "(self:POSITIONAL_OR_KEYWORD, path:POSITIONAL_OR_KEYWORD='')",
    "get": "(self:POSITIONAL_OR_KEYWORD, url:POSITIONAL_OR_KEYWORD, params:POSITIONAL_OR_KEYWORD=None, kwargs:VAR_KEYWORD)",
    "get_adapter": "(self:POSITIONAL_OR_KEYWORD, url:POSITIONAL_OR_KEYWORD)",
    "get_redirect_target": "(self:POSITIONAL_OR_KEYWORD, response:POSITIONAL_OR_KEYWORD)",
    "head": "(self:POSITIONAL_OR_KEYWORD, url:POSITIONAL_OR_KEYWORD, kwargs:VAR_KEYWORD)",
    "lock": "(self:POSITIONAL_OR_KEYWORD, url:POSITIONAL_OR_KEYWORD, scope:KEYWORD_ONLY='exclusive', owner:KEYWORD_ONLY=None, depth:KEYWORD_ONLY='infinity', lock_timeout:KEYWORD_ONLY=600, refresh:KEYWORD_ONLY=None, kwargs:VAR_KEYWORD)",
    "merge_environment_settings": "(self:POSITIONAL_OR_KEYWORD, url:POSITIONAL_OR_KEYWORD, proxies:POSITIONAL_OR_KEYWORD, stream:POSITIONAL_OR_KEYWORD, verify:POSITIONAL_OR_KEYWORD, cert:POSITIONAL_OR_KEYWORD)",
    "mkcol": "(self:POSITIONAL_OR_KEYWORD, url:POSITIONAL_OR_KEYWORD, data:POSITIONAL_OR_KEYWORD=None, kwargs:VAR_KEYWORD)",
    "mount": "(self:POSITIONAL_OR_KEYWORD, prefix:POSITIONAL_OR_KEYWORD, adapter:POSITIONAL_OR_KEYWORD)",
    "move": "(self:POSITIONAL_OR_KEYWORD, url:POSITIONAL_OR_KEYWORD, destination:POSITIONAL_OR_KEYWORD, overwrite:KEYWORD_ONLY=False, kwargs:VAR_KEYWORD)",
    "options": "(self:POSITIONAL_OR_KEYWORD, url:POSITIONAL_OR_KEYWORD, kwargs:VAR_KEYWORD)",
    "prepare_request": "(self:POSITIONAL_OR_KEYWORD, request:POSITIONAL_OR_KEYWORD)",
    "propfind": "(self:POSITIONAL_OR_KEYWORD, url:POSITIONAL_OR_KEYWORD, data:POSITIONAL_OR_KEYWORD=None, depth:KEYWORD_ONLY, props:KEYWORD_ONLY=None, all_prop:KEYWORD_ONLY=False, include:KEYWORD_ONLY=None, kwargs:VAR_KEYWORD)",
    "proppatch": "(self:POSITIONAL_OR_KEYWORD, url:POSITIONAL_OR_KEYWORD, data:POSITIONAL_OR_KEYWORD=None, set_props:KEYWORD_ONLY=None, remove_props:KEYWORD_ONLY=None, kwargs:VAR_KEYWORD)",
    "put": "(self:POSITIONAL_OR_KEYWORD, url:POSITIONAL_OR_KEYWORD, data:POSITIONAL_OR_KEYWORD=None, if_match:KEYWORD_ONLY=None, overwrite:KEYWORD_ONLY=None, kwargs:VAR_KEYWORD)",
    "request": "(self:POSITIONAL_OR_KEYWORD, method:POSITIONAL_OR_KEYWORD, url:POSITIONAL_OR_KEYWORD, args:VAR_POSITIONAL, redirect_policy:KEYWORD_ONLY=None, raise_on_error:KEYWORD_ONLY=None, kwargs:VAR_KEYWORD)",
    "resolve_url": "(self:POSITIONAL_OR_KEYWORD, url:POSITIONAL_OR_KEYWORD, add_trailing_slash:POSITIONAL_OR_KEYWORD=False)",
    "send": "(self:POSITIONAL_OR_KEYWORD, request:POSITIONAL_OR_KEYWORD, kwargs:VAR_KEYWORD)",
    "unlock": "(self:POSITIONAL_OR_KEYWORD, url:POSITIONAL_OR_KEYWORD, token:POSITIONAL_OR_KEYWORD, kwargs:VAR_KEYWORD)",
}


def _signature(function: object) -> str:
    parts = []
    for p in inspect.signature(function).parameters.values():  # type: ignore[arg-type]
        default = "" if p.default is p.empty else f"={p.default!r}"
        parts.append(f"{p.name}:{p.kind.name}{default}")
    return "(" + ", ".join(parts) + ")"


def test_the_package_namespace_is_pinned() -> None:
    assert sorted(webdav.__all__) == _PACKAGE_ALL


def test_the_fs_namespace_is_pinned() -> None:
    assert sorted(webdav.fs.__all__) == _FS_ALL


def test_the_session_module_namespace_is_pinned() -> None:
    assert sorted(webdav.session.__all__) == _SESSION_ALL


def test_a_session_instance_carries_exactly_these_public_attributes() -> None:
    assert sorted(n for n in vars(Session()) if not n.startswith("_")) == (
        _SESSION_INSTANCE_ATTRIBUTES
    )


def test_the_public_members_of_session_are_pinned() -> None:
    properties = []
    methods = {}
    for name in dir(Session):
        if name.startswith("_"):
            continue
        member = inspect.getattr_static(Session, name)
        if isinstance(member, property):
            properties.append(name)
        else:
            assert callable(member), f"unexpected public non-callable {name!r}"
            methods[name] = _signature(getattr(Session, name))
    assert sorted(properties) == _SESSION_PROPERTIES
    assert methods == _SESSION_METHODS
