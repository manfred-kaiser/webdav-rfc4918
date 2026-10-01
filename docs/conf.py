"""Sphinx configuration."""

import datetime
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from webdav import __version__

project = "webdav-rfc4918"
author = "Manfred Kaiser"
# Sphinx's own mandated config variable name - can't be renamed.
copyright = (  # noqa: A001 # pylint: disable=redefined-builtin
    f"{datetime.datetime.now(tz=datetime.UTC).year}, {author}"
)
version = __version__

extensions = [
    "sphinx_copybutton",
    "sphinx.ext.autodoc",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "myst_parser",
]

myst_enable_extensions = ["colon_fence"]
myst_heading_anchors = 3

html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "logo_only": False,
    "navigation_depth": 3,
}

html_context = {
    "display_github": True,
    "github_user": "manfred-kaiser",
    "github_repo": "webdav-rfc4918",
    "github_version": "main",
    "conf_py_path": "/docs/",
}

html_static_path = ["_static"]
templates_path = ["_templates"]

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "requests": ("https://requests.readthedocs.io/en/latest", None),
    "fsspec": ("https://filesystem-spec.readthedocs.io/en/stable", None),
}

master_doc = "index"
autosectionlabel_maxdepth = 1
autoclass_content = "both"

copybutton_prompt_text = r">>> |\.\.\. |\$ "
copybutton_prompt_is_regexp = True

language = "en"
exclude_patterns: list[str] = []
