"""Tests for core.environment — detection helpers must never raise."""

from __future__ import annotations

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core import environment


class TestDetection(unittest.TestCase):
    def test_predicates_return_bools(self):
        for value in (environment.is_termux(), environment.is_android(),
                      environment.is_root(), environment.termux_api_ready()):
            self.assertIsInstance(value, bool)

    def test_have_finds_this_interpreter(self):
        self.assertTrue(environment.have(sys.executable))
        self.assertTrue(environment.have("python") or environment.have("python3"))

    def test_have_rejects_nonsense(self):
        self.assertFalse(environment.have("definitely-not-a-real-binary-xyz"))
        self.assertFalse(environment.have(""))

    def test_prefix_is_a_string(self):
        self.assertIsInstance(environment.prefix(), str)
        self.assertTrue(environment.prefix())

    def test_capabilities_shape(self):
        caps = environment.capabilities()
        for key in ("platform", "python", "termux", "android", "root", "prefix",
                    "termux_api", "tools"):
            self.assertIn(key, caps)
        self.assertIsInstance(caps["tools"], dict)
        self.assertEqual(set(caps["tools"]), set(environment.OPTIONAL_TOOLS))

    def test_termux_respects_the_version_env_var(self):
        original = os.environ.get("TERMUX_VERSION")
        os.environ["TERMUX_VERSION"] = "0.118"
        try:
            self.assertTrue(environment.is_termux())
        finally:
            if original is None:
                os.environ.pop("TERMUX_VERSION", None)
            else:
                os.environ["TERMUX_VERSION"] = original

    def test_missing_tools_is_a_list_of_pairs(self):
        missing = environment.missing_tools()
        self.assertIsInstance(missing, list)
        for entry in missing:
            self.assertEqual(len(entry), 2)

    def test_summary_line_mentions_python(self):
        self.assertIn("Python", environment.summary_line())

    def test_android_version_is_str_or_none(self):
        value = environment.android_version()
        self.assertTrue(value is None or isinstance(value, str))


if __name__ == "__main__":
    unittest.main()
