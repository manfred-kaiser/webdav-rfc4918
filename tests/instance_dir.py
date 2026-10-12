"""The directory a throwaway Apache/nginx instance lives in (shared by both ``*_instance.py``)."""

import os
import stat
from pathlib import Path


def ensure_private_dir(path: Path) -> None:
    """Create ``path`` (mode 0700) if it is missing; refuse one that somebody else could have prepared.

    A predictable name in a shared ``/tmp`` lets another local user plant the
    directory (or a symlink to one of the caller's) before the instance is
    written into it: files would be overwritten through the link, or a
    ``httpd.conf`` swapped before the server starts. So an existing directory
    must be a real one, owned by the caller and not writable by others (a group
    that is the caller's own primary group, as ``mkdir`` leaves under ``umask 002``,
    does not count as others). (POSIX owner/mode only; Windows has no such notion here.)

    Raises:
        RuntimeError: ``path`` is a symlink, not owned by the current user, or
            writable by group/others.

    """
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = os.lstat(path)
    if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
        msg = f"{path} is a symlink or not a directory; refusing to use it as an instance directory"
        raise RuntimeError(msg)
    others = (
        stat.S_IWOTH | (0 if info.st_gid == os.getgid() else stat.S_IWGRP)
        if hasattr(os, "getgid")
        else stat.S_IWGRP | stat.S_IWOTH
    )
    if hasattr(os, "getuid") and (info.st_uid != os.getuid() or info.st_mode & others):
        msg = (
            f"{path} is not owned by you or is writable by others; refusing to use it "
            "as an instance directory (remove it, or pick another with --instance-dir)"
        )
        raise RuntimeError(msg)
