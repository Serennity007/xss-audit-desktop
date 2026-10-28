import json
import tempfile
import unittest
from pathlib import Path

from xss_audit.config import ScanConfig, load_config


class ConfigTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def config(self, text):
        path = self.root / ".xss-audit.toml"
        path.write_text(text, encoding="utf-8")
        return load_config(self.root)

    def test_missing_default_uses_existing_scan_budgets(self):
        config = load_config(self.root)
        self.assertEqual(config.to_dict(), {
            "include": [], "exclude": [], "max_file_bytes": 1048576,
            "max_total_bytes": 104857600, "max_files": 10000,
            "max_matches": 10000, "strict": True,
        })
        self.assertTrue(config.allows_file("src/example.js"))
        self.assertFalse(config.excludes_directory("node_modules"))
        self.assertNotIn(str(self.root), json.dumps(config.to_dict()))

    def test_default_discovery_and_partial_overrides(self):
        config = self.config('[scan]\ninclude = ["src/**/*.js"]\nexclude = ["src/generated/**"]\nmax_files = 25\nstrict = false\n')
        self.assertEqual(config.include, ("src/**/*.js",))
        self.assertEqual(config.max_files, 25)
        self.assertEqual(config.max_matches, 10000)
        self.assertFalse(config.strict)
        self.assertTrue(config.allows_file("src/app.js"))
        self.assertFalse(config.allows_file("src/generated/app.js"))

    def test_explicit_paths_resolve_from_project_or_are_absolute(self):
        nested = self.root / "settings"
        nested.mkdir()
        target = nested / "audit.toml"
        target.write_text("[scan]\nmax_matches = 7\n", encoding="utf-8")
        self.assertEqual(load_config(self.root, "settings/audit.toml").max_matches, 7)
        self.assertEqual(load_config(self.root, target).max_matches, 7)
        with self.assertRaisesRegex(ValueError, "does not exist"):
            load_config(self.root, "missing.toml")

    def test_double_star_matches_root_and_nested_files(self):
        config = ScanConfig(include=("**/*.js",), exclude=("**/*.test.js", "**/generated/**"))
        for rel in ("app.js", "src/app.js", "src/deep/app.js", "中文/app.js"):
            with self.subTest(rel=rel):
                self.assertTrue(config.allows_file(rel))
        for rel in ("app.py", "app.test.js", "src/app.test.js", "generated/app.js", "src/generated/app.js"):
            with self.subTest(rel=rel):
                self.assertFalse(config.allows_file(rel))
        self.assertTrue(config.excludes_directory("generated"))
        self.assertTrue(config.excludes_directory("src/generated"))
        self.assertTrue(config.excludes_directory("src/generated/deep"))
        self.assertFalse(config.excludes_directory("src/generated2"))

    def test_single_star_is_root_anchored_and_does_not_cross_directories(self):
        config = ScanConfig(include=("src/*.js",), exclude=("src/*.test.js",))
        self.assertTrue(config.allows_file("src/app.js"))
        self.assertFalse(config.allows_file("src/deep/app.js"))
        self.assertFalse(config.allows_file("other/src/app.js"))
        self.assertFalse(config.allows_file("src/app.test.js"))
        self.assertFalse(config.excludes_directory("src"))
        self.assertFalse(config.excludes_directory("src/deep"))

    def test_directory_exclusions_apply_to_descendants_and_win_over_include(self):
        config = ScanConfig(include=("**/*.py",), exclude=("./src/generated/",))
        self.assertEqual(config.exclude, ("src/generated",))
        self.assertTrue(config.excludes_directory("src/generated/"))
        self.assertFalse(config.allows_file("src/generated/deep/app.py"))
        self.assertTrue(config.allows_file("src/generated2/app.py"))
        self.assertTrue(config.allows_file("src/app.py"))

    def test_question_and_character_class_globs(self):
        config = ScanConfig(include=("src/[ab]?.js",))
        self.assertTrue(config.allows_file("src/a1.js"))
        self.assertTrue(config.allows_file("src/b2.js"))
        self.assertFalse(config.allows_file("src/c1.js"))
        self.assertFalse(config.allows_file("src/a10.js"))

    def test_unknown_sections_keys_and_invalid_types_are_rejected(self):
        cases = [
            '[ai]\napi_key = "must-not-be-accepted"',
            '[scan]\nmax_file_size = 10',
            'scan = []',
            '[scan]\ninclude = "**/*.js"',
            '[scan]\nexclude = [1]',
            '[scan]\nstrict = "true"',
            '[scan]\nstrict = 1',
            '[scan]\nmax_files = true',
            '[scan]\nmax_files = 1.5',
            '[scan]\nmax_files = "10"',
            '[scan]\nmax_matches = 0',
            '[scan]\nmax_total_bytes = -1',
            '[scan]\nmax_file_bytes = 0',
        ]
        for text in cases:
            with self.subTest(text=text), self.assertRaises(ValueError):
                self.config(text)

    def test_globs_must_be_relative_posix_paths(self):
        for pattern in ("", "/src/**", "../src/**", "src/../**", "src//**", "src/./**", "C:/src/**", r"src\**", "src/\n**"):
            with self.subTest(pattern=pattern), self.assertRaises(ValueError):
                ScanConfig(exclude=(pattern,))

    def test_bad_toml_and_unreadable_encoding_have_actionable_errors(self):
        with self.assertRaisesRegex(ValueError, "Invalid scan configuration"):
            self.config("[scan\nmax_files = 1")
        path = self.root / ".xss-audit.toml"
        path.write_bytes(b"\xff\xfe")
        with self.assertRaisesRegex(ValueError, "Cannot read scan configuration"):
            load_config(self.root)
        path.unlink()
        path.mkdir()
        with self.assertRaisesRegex(ValueError, "Cannot read scan configuration"):
            load_config(self.root)

    def test_windows_utf8_bom_and_empty_config_are_supported(self):
        path = self.root / ".xss-audit.toml"
        path.write_text("[scan]\nmax_files = 9\n", encoding="utf-8-sig")
        self.assertEqual(load_config(self.root).max_files, 9)
        self.assertEqual(self.config(""), ScanConfig())


if __name__ == "__main__":
    unittest.main()
