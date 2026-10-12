"""Every path method fsspec has refuses a URL for another server - also one a later fsspec adds.

The check sits in ``_strip_protocol`` (see ``server_aware``), which fsspec's methods call on the
instance. If a release of fsspec adds a method that takes a path and does not go through it, this
fails, and the method needs a check of its own in ``GuardedFileSystem``.
"""

import inspect

from fsspec.spec import AbstractFileSystem

from webdav.fsspec import WebdavFileSystem

FOREIGN = "webdavs://other.example/secret.txt"
FIRST_ARGUMENTS = ("path", "rpath", "path1", "root", "urlpath")
#: Take a path but never touch a server with it, or need more than a path.
NOT_CHECKED = {"invalidate_cache", "sign", "get_file", "cat_file_ranges"}


def test_every_path_method_of_fsspec_refuses_another_server() -> None:
    fs = WebdavFileSystem("http://127.0.0.1:9", retry=False, timeout=(0.05, 0.05))
    not_refused = []
    tried = 0
    for name, member in inspect.getmembers(
        AbstractFileSystem, predicate=inspect.isfunction
    ):
        if name.startswith("_") or name in NOT_CHECKED:
            continue
        params = list(inspect.signature(member).parameters.values())[1:]
        if not params or params[0].name not in FIRST_ARGUMENTS:
            continue
        if any(
            p.default is p.empty
            and p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
            for p in params[1:]
        ):
            continue  # needs more than a path
        tried += 1
        try:
            result = getattr(fs, name)(FOREIGN)
            if inspect.isgenerator(result):
                list(result)
        except ValueError as exc:
            if "bound to one server" not in str(exc):
                not_refused.append(name)
        except (
            Exception
        ):  # noqa: BLE001 - anything else means it went on towards the server
            not_refused.append(name)
        else:
            not_refused.append(name)
    assert (
        tried >= 25
    ), "the canary found hardly any methods: has fsspec changed its signatures?"
    assert not_refused == []
