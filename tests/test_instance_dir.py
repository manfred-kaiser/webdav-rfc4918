"""The private instance directory of the Apache/nginx test helpers."""

import os
from pathlib import Path

import pytest

from tests.instance_dir import ensure_private_dir


@pytest.mark.skipif(not hasattr(os, "getuid"), reason="POSIX owners and modes")
class TestInstanceDirectory:
    """What ``ensure_private_dir`` accepts and what it refuses."""

    def test_a_new_directory_is_private(self, tmp_path: Path) -> None:
        """A directory it creates is ``0700``."""
        target = tmp_path / "new" / "instance"
        ensure_private_dir(target)
        assert target.stat().st_mode & 0o777 == 0o700

    def test_an_existing_directory_of_ours_is_accepted(self, tmp_path: Path) -> None:
        """Asking twice is fine."""
        ensure_private_dir(tmp_path)
        ensure_private_dir(tmp_path)

    def test_a_symlink_is_refused(self, tmp_path: Path) -> None:
        """A link in the place of the directory could lead anywhere."""
        victim = tmp_path / "victim"
        victim.mkdir()
        link = tmp_path / "instance"
        link.symlink_to(victim)
        with pytest.raises(RuntimeError, match="symlink"):
            ensure_private_dir(link)

    def test_a_directory_others_can_write_to_is_refused(self, tmp_path: Path) -> None:
        """Anyone could replace what the instance runs from."""
        shared = tmp_path / "shared"
        shared.mkdir()
        shared.chmod(0o777)
        with pytest.raises(RuntimeError, match="writable by others"):
            ensure_private_dir(shared)

    def test_a_directory_of_another_user_is_refused(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A directory that another user made is not ours to start an instance in."""
        monkeypatch.setattr(os, "getuid", lambda: tmp_path.stat().st_uid + 1)
        with pytest.raises(RuntimeError, match="not owned by you"):
            ensure_private_dir(tmp_path)


@pytest.mark.skipif(not hasattr(os, "getgid"), reason="POSIX owner and mode")
def test_a_directory_with_the_callers_group_writable_is_fine(tmp_path: Path) -> None:
    """``mkdir`` leaves 0775 under ``umask 002``, the default of several distributions."""
    target = tmp_path / "instance"
    target.mkdir()
    target.chmod(0o770)
    ensure_private_dir(target)


@pytest.mark.skipif(not hasattr(os, "getgid"), reason="POSIX owner and mode")
def test_a_directory_others_can_write_is_refused(tmp_path: Path) -> None:
    target = tmp_path / "instance"
    target.mkdir()
    target.chmod(0o707)
    with pytest.raises(RuntimeError, match="writable by others"):
        ensure_private_dir(target)
