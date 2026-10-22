from pathlib import Path
import tempfile
import unittest

from divalia.config import Config
from divalia.ai.base_provider import create_provider
from divalia.ai.router import ModelRouter


class ConfigTests(unittest.TestCase):
    def load_text(self, text):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "divalia.toml"
            path.write_text(text, encoding="utf-8")
            return Config.load(path)

    def test_malformed_nested_settings_fail_with_actionable_value_errors(self):
        cases = [
            ('feeds = ["rss"]', "feed"),
            ('feeds = [{kind = ["rss"], url = "https://example.com/feed"}]', "kind"),
            ('feeds = [{kind = "rss", url = 5}]', "URL"),
            ('[ai]\nheavy = "openai"', "ai.heavy"),
            ('[ai]\ntimeout = "120"', "ai.timeout"),
            ('[ai]\ntimeout = true', "ai.timeout"),
            ('[ai]\ntimeout = nan', "ai.timeout"),
            ('[ai]\ntimeout = inf', "ai.timeout"),
            ('[ai]\ntimeout = ' + "9" * 300, "ai.timeout"),
            ('[ai]\nallow_remote = "false"', "allow_remote"),
            ('[ai]\nkey_env = "not a variable"', "key_env"),
            ('[ai.light]\nlight_model = ["small"]', "light_model"),
            ('[ai.heavy]\nprovider = 5', "provider"),
            ('[app]\nstate_dir = []', "state_dir"),
            ('[app]\nstate_dir = ""', "state_dir"),
            ('[angerona]\ndata_dir = 5', "data_dir"),
            ('[angerona]\npython = []', "python"),
            ('[sandbox]\nimage = 5', "sandbox.image"),
        ]
        for text, message in cases:
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, message):
                self.load_text(text)

    def test_role_overrides_keep_explicit_privacy_boundary(self):
        config = self.load_text(
            '[ai]\nprovider = "ollama"\nlight_model = "small"\nheavy_model = "large"\n'
            'allow_remote = false\n[ai.heavy]\nprovider = "openai"\nallow_remote = true\n'
            'heavy_model = "configured-model"\nkey_env = "CUSTOM_API_KEY"\n'
        )
        router = ModelRouter(config.ai)
        self.assertFalse(router.providers["light"].allow_remote)
        self.assertTrue(router.providers["heavy"].allow_remote)
        self.assertEqual(router.providers["heavy"].heavy_model, "configured-model")
        self.assertEqual(router.providers["heavy"].key_env, "CUSTOM_API_KEY")

    def test_relative_paths_resolve_against_configuration_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "divalia.toml"
            path.write_text('[app]\nstate_dir = "state"\n[angerona]\ndata_dir = "Angerona"',
                            encoding="utf-8")
            config = Config.load(path)
            self.assertEqual(config.state_dir, Path(directory) / "state")
            self.assertEqual(config.angerona_data_dir, Path(directory) / "Angerona")

    def test_adapter_construction_rejects_invalid_values_without_coercing_them(self):
        base = {"light_model": "small", "heavy_model": "large"}
        for key, value in [("timeout", "120"), ("timeout", True), ("timeout", float("nan")),
                           ("timeout", 10 ** 300), ("light_model", []), ("heavy_model", 5),
                           ("key_env", ["MY_KEY"]), ("endpoint", []), ("provider", [])]:
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                create_provider({**base, key: value})
        for config in [[], {"light": []}, {"heavy": "openai"}]:
            with self.subTest(config=config), self.assertRaises(ValueError):
                ModelRouter(config)


if __name__ == "__main__":
    unittest.main()
