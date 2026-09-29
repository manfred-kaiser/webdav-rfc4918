"""A real WebDAV server (wsgidav + cheroot) for tests, run on an ephemeral port."""

import threading
from collections.abc import Iterator
from contextlib import contextmanager

from cheroot import wsgi
from wsgidav.wsgidav_app import WsgiDAVApp

AUTH = "user1", "password1"


def get_server_address(srvr: wsgi.Server) -> str:
    """Return the base URL of a bound server."""
    host, port = srvr.bind_addr
    return f"http://{host}:{port}"


@contextmanager
def run_server_on_thread(
    srvr: wsgi.Server,
) -> Iterator[tuple[wsgi.Server, threading.Thread]]:
    """Run a cheroot server on a background thread for the duration of the block."""
    srvr.prepare()
    thread = threading.Thread(target=srvr.serve)
    thread.daemon = True
    thread.start()

    try:
        yield srvr, thread
    finally:
        srvr.stop()
    thread.join()


def create_wsgidav_app(directory: str, *, require_auth: bool = True) -> WsgiDAVApp:
    """Build a WsgiDAVApp serving ``directory``, with Class 2 (locking) support."""
    config = {
        "provider_mapping": {"/": directory},
        "lock_storage": True,  # enables LOCK/UNLOCK (RFC 4918 Class 2)
        "property_manager": True,  # enables PROPPATCH-settable custom/dead properties
        "verbose": 0,
        "logging": {"enable_loggers": []},
    }
    if require_auth:
        config["http_authenticator"] = {
            "domain_controller": None,  # use simple_dc with the users below
            "accept_basic": True,
            "accept_digest": False,
            "default_to_digest": False,
        }
        config["simple_dc"] = {"user_mapping": {"*": {AUTH[0]: {"password": AUTH[1]}}}}
    else:
        config["http_authenticator"] = {"domain_controller": None}
        config["simple_dc"] = {"user_mapping": {"*": True}}
    return WsgiDAVApp(config)


@contextmanager
def webdav_server(directory: str, *, require_auth: bool = True) -> Iterator[str]:
    """Run a real WebDAV server against ``directory`` for the duration of the block.

    Yields the server's base URL.
    """
    app = create_wsgidav_app(directory, require_auth=require_auth)
    server = wsgi.Server(("127.0.0.1", 0), app)
    with run_server_on_thread(server):
        yield get_server_address(server)
