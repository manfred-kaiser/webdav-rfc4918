"""The Nextcloud test container is reachable from the host only."""

import types

import pytest

from tests import nextcloud_instance


def test_the_nextcloud_container_is_published_on_loopback_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Docker publishes ``-p 8767:80`` on every interface, past the host firewall."""
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> types.SimpleNamespace:
        commands.append(command)
        return types.SimpleNamespace(returncode=1, stdout="", stderr="")

    monkeypatch.setattr(nextcloud_instance, "missing_prerequisites", list)
    monkeypatch.setattr(nextcloud_instance, "_docker_binary", lambda: "docker")
    monkeypatch.setattr(nextcloud_instance.subprocess, "run", fake_run)
    with pytest.raises(RuntimeError, match="docker run failed"):
        nextcloud_instance.start()
    (run,) = (c for c in commands if c[1] == "run")
    assert run[run.index("-p") + 1] == "127.0.0.1:8767:80"
