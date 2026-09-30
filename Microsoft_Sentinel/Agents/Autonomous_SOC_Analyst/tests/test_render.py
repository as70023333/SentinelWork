"""Report rendering must never let attacker-controlled text become markup."""
from __future__ import annotations

import unittest

from soc_agent.render import markdown_to_safe_html


class RenderTests(unittest.TestCase):
    def test_html_is_escaped(self):
        out = markdown_to_safe_html("cmd: <script>alert(1)</script> <img src=x onerror=alert(1)>")
        self.assertNotIn("<script", out)
        self.assertNotIn("<img", out)
        self.assertIn("&lt;script&gt;", out)

    def test_links_and_images_disabled(self):
        out = markdown_to_safe_html("[click](javascript:alert(1)) ![p](http://evil/p.png) <http://evil>")
        self.assertNotIn("<a ", out)
        self.assertNotIn("<img", out)

    def test_code_is_escaped_once(self):
        out = markdown_to_safe_html('```kql\nT | where x > 1 and y == "<b>"\n```\n\nInline `a<b`')
        self.assertIn("x &gt; 1", out)
        self.assertIn("&lt;b&gt;", out)
        self.assertNotIn("&amp;gt;", out)
        self.assertIn("<code>a&lt;b</code>", out)

    def test_tables_render(self):
        out = markdown_to_safe_html("| a | b |\n|---|---|\n| `x` | <i>y</i> |")
        self.assertIn("<table>", out)
        self.assertIn("&lt;i&gt;y&lt;/i&gt;", out)


if __name__ == "__main__":
    unittest.main()
