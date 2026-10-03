"""Jinja2 template environment for the admin panel."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

templates_dir = Path(__file__).parent / "templates"

TEMPLATE_ENV = Environment(
    loader=FileSystemLoader(str(templates_dir)),
    # Auto-escape HTML in .html templates: every user-controlled value
    # (usernames, target names) is rendered here, so escaping is not
    # optional.
    autoescape=select_autoescape(
        enabled_extensions=("html", "htm", "xml"),
        default_for_string=True,
    ),
    trim_blocks=True,
    lstrip_blocks=True,
)

templates = TEMPLATE_ENV.get_template


def render(name: str, **context) -> str:
    """Render a template with shared context applied."""
    return TEMPLATE_ENV.get_template(name).render(**context)