"""Safe markdown rendering.

Reports embed attacker-controlled strings (command lines, file names, email subjects), so the
renderer (1) escapes raw HTML outside code, (2) lets markdown escape code itself, and
(3) disables link/image syntax entirely so nothing can smuggle a javascript: URL or a
tracking pixel into the dashboard or the Sentinel comment.
"""
from __future__ import annotations

import re
from html import escape

import markdown as md

_CODE = re.compile(r"(```.*?```|`[^`\n]*`)", re.S)
_DISABLED_INLINE = ("link", "image_link", "image_reference", "reference", "short_reference",
                    "short_image_ref", "autolink", "automail", "html", "entity")


def _renderer() -> md.Markdown:
    r = md.Markdown(extensions=["tables", "fenced_code"])
    for name in _DISABLED_INLINE:
        if name in r.inlinePatterns:
            r.inlinePatterns.deregister(name)
    if "html_block" in r.preprocessors:
        r.preprocessors.deregister("html_block")
    return r


def markdown_to_safe_html(text: str) -> str:
    parts = _CODE.split(text or "")
    safe = "".join(p if i % 2 else escape(p, quote=False) for i, p in enumerate(parts))
    return _renderer().convert(safe)
