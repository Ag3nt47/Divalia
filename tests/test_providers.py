from __future__ import annotations

import json
import os
import unittest
import urllib.error
from unittest.mock import AsyncMock, MagicMock, patch

from divalia.ai.base_provider import (
    BaseProvider,
    CompatibleProvider,
    ProviderError,
    _NoRedirect,
    create_provider,
    validate_endpoint,
)
from divalia.ai.ollama_provider import OllamaProvider
from divalia.ai.remote_provider import RemoteProvider
from divalia.ai.router import ModelRouter


class EndpointTests(unittest.TestCase):
    def test_local_provider_requires_literal_loopback_and_no_embedded_credentials(self):
        for url in ["http://127.0.0.1:11434", "http://[::1]:1234/v1"]:
            self.assertEqual(validate_endpoint(url), url)
        for url in [
            "http://localhost:11434",
            "http://192.168.1.5",
            "https://example.org",
            "http://user:secret@127.0.0.1",
            "http://127.0.0.1?q=secret",
            "file:///tmp/model",
        ]:
            with self.subTest(url=url), self.assertRaises(ValueError):
                validate_endpoint(url)
        with self.assertRaises(ValueError):
            validate_endpoint("http://example.org", remote=True)

    def test_remote_providers_require_explicit_opt_in(self):
        for kind in ["openai", "anthropic", "gemini"]:
            for allow in [False, "true", 1, None]:
                with self.subTest(kind=kind, allow=allow), self.assertRaises(PermissionError):
                    create_provider(
                        {
                            "provider": kind,
                            "light_model": "light",
                            "heavy_model": "heavy",
                            "allow_remote": allow,
                        }
                    )

    def test_redirects_are_rejected_before_credentials_can_reach_new_host(self):
        with self.assertRaises(ProviderError):
            _NoRedirect().redirect_request(
                None, None, 302, "redirect", {}, "https://attacker.example"
            )


class ProviderBoundaryTests(unittest.IsolatedAsyncioTestCase):
    async def test_ollama_and_compatible_use_role_models_with_bounded_nonstreaming_requests(self):
        cases = [
            (OllamaProvider, "http://127.0.0.1:11434", {"response": "output"}, "/api/generate"),
            (
                CompatibleProvider,
                "http://127.0.0.1:1234/v1",
                {"choices": [{"message": {"content": "output"}}]},
                "/chat/completions",
            ),
        ]
        for adapter, endpoint, response, path in cases:
            provider = adapter(endpoint, light_model="small", heavy_model="reasoner")
            with (
                self.subTest(adapter=adapter.__name__),
                patch.object(
                    provider, "request", new_callable=AsyncMock, return_value=response
                ) as request,
            ):
                self.assertEqual(
                    await provider.generate("evidence", system="policy", role="light"), "output"
                )
                call_path, payload = request.call_args.args
                self.assertEqual(call_path, path)
                self.assertEqual(payload["model"], "small")
                self.assertIs(payload["stream"], False)
                self.assertEqual(provider.model("heavy"), "reasoner")

    async def test_invalid_role_and_invalid_output_are_rejected(self):
        provider = OllamaProvider(
            "http://127.0.0.1:11434", light_model="small", heavy_model="large"
        )
        with self.assertRaises(ValueError):
            await provider.generate("data", role="other")
        for response in [{}, {"response": None}, {"response": "x" * 100001}, []]:
            with (
                self.subTest(response=str(response)[:40]),
                patch.object(provider, "request", new_callable=AsyncMock, return_value=response),
                self.assertRaises(ProviderError),
            ):
                await provider.generate("data")

    async def test_model_download_needs_consent_and_success_confirmation(self):
        provider = OllamaProvider(
            "http://127.0.0.1:11434", light_model="small", heavy_model="large"
        )
        with patch.object(provider, "request", new_callable=AsyncMock) as request:
            with self.assertRaises(PermissionError):
                await provider.pull("small")
            request.assert_not_called()
        with (
            patch.object(
                provider, "request", new_callable=AsyncMock, return_value={"status": "failed"}
            ),
            self.assertRaises(ProviderError),
        ):
            await provider.pull("small", consent=True)

    async def test_router_does_not_fallback_after_local_failure(self):
        class Adapter(BaseProvider):
            def __init__(self, fail=False):
                self.fail, self.calls = fail, 0

            async def generate(self, prompt, *, system="", role="heavy"):
                self.calls += 1
                if self.fail:
                    raise ProviderError("offline")
                return "heavy-result"

        light, heavy = Adapter(fail=True), Adapter()
        with patch("divalia.ai.router.create_provider", side_effect=[light, heavy]):
            router = ModelRouter({})
        with self.assertRaises(ProviderError):
            await router.generate("sensitive telemetry", role="light")
        self.assertEqual(light.calls, 1)
        self.assertEqual(heavy.calls, 0)

    async def test_remote_protocols_use_expected_text_boundaries(self):
        cases = [
            ("openai", {"choices": [{"message": {"content": "answer"}}]}, "/chat/completions"),
            ("anthropic", {"content": [{"type": "text", "text": "answer"}]}, "/messages"),
            (
                "gemini",
                {"candidates": [{"content": {"parts": [{"text": "answer"}]}}]},
                "/models/test-model:generateContent",
            ),
        ]
        for kind, response, expected_path in cases:
            provider = RemoteProvider(
                kind,
                allow_remote=True,
                key_env="DIVALIA_TEST_CREDENTIAL",
                light_model="test-model",
                heavy_model="test-model",
            )
            with (
                self.subTest(kind=kind),
                patch.dict(os.environ, {"DIVALIA_TEST_CREDENTIAL": "synthetic-test-token"}),
                patch.object(provider, "_request_sync", return_value=response) as request,
            ):
                output = await provider.generate("evidence", system="defensive policy")
                self.assertEqual(output, "answer")
                self.assertEqual(request.call_args.args[0], expected_path)
                serialized = json.dumps(request.call_args.args[1])
                self.assertIn("evidence", serialized)
                self.assertNotIn("synthetic-test-token", serialized)

    async def test_malformed_remote_shapes_raise_provider_error(self):
        cases = [
            ("anthropic", {"content": [None]}),
            ("anthropic", {"content": "malformed"}),
            ("openai", {"choices": []}),
            ("gemini", {"candidates": []}),
        ]
        for kind, response in cases:
            provider = RemoteProvider(
                kind,
                allow_remote=True,
                key_env="DIVALIA_TEST_CREDENTIAL",
                light_model="test-model",
                heavy_model="test-model",
            )
            with (
                self.subTest(kind=kind, response=response),
                patch.dict(os.environ, {"DIVALIA_TEST_CREDENTIAL": "synthetic"}),
                patch.object(provider, "_request_sync", return_value=response),
                self.assertRaises(ProviderError),
            ):
                await provider.generate("evidence")

    def test_http_transport_disables_proxy_environment_and_bounds_read(self):
        provider = CompatibleProvider(
            "http://127.0.0.1:1234/v1",
            light_model="small",
            heavy_model="heavy",
            key_env="DIVALIA_TEST_CREDENTIAL",
        )
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b'{"ok": true}'
        opener = MagicMock()
        opener.open.return_value = response
        with (
            patch.dict(os.environ, {"DIVALIA_TEST_CREDENTIAL": "synthetic-test-token"}),
            patch(
                "divalia.ai.base_provider.urllib.request.build_opener", return_value=opener
            ) as build,
        ):
            self.assertEqual(
                provider._request_sync("/chat/completions", {"text": "evidence"}), {"ok": True}
            )
        self.assertEqual(build.call_args.args[0].proxies, {})
        request = opener.open.call_args.args[0]
        self.assertEqual(request.get_header("Authorization"), "Bearer synthetic-test-token")
        response.read.assert_called_once_with(1024 * 1024 + 1)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], 120)

    def test_missing_credential_oversized_response_and_http_error_do_not_echo_secrets(self):
        provider = CompatibleProvider(
            "http://127.0.0.1:1234/v1",
            light_model="small",
            heavy_model="heavy",
            key_env="DIVALIA_TEST_CREDENTIAL",
        )
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("divalia.ai.base_provider.urllib.request.build_opener") as build,
        ):
            with self.assertRaises(ProviderError):
                provider._request_sync("/chat/completions", {})
            build.assert_not_called()
        provider.key_env = ""
        response = MagicMock()
        response.__enter__.return_value = response
        response.read.return_value = b"x" * (1024 * 1024 + 1)
        opener = MagicMock()
        opener.open.return_value = response
        with (
            patch("divalia.ai.base_provider.urllib.request.build_opener", return_value=opener),
            self.assertRaises(ProviderError),
        ):
            provider._request_sync("/chat/completions", {})
        opener.open.side_effect = urllib.error.HTTPError(
            "https://example.org?secret=hidden", 429, "secret hidden", {}, None
        )
        with (
            patch("divalia.ai.base_provider.urllib.request.build_opener", return_value=opener),
            self.assertRaises(ProviderError) as raised,
        ):
            provider._request_sync("/chat/completions", {})
        self.assertIn("429", str(raised.exception))
        self.assertNotIn("hidden", str(raised.exception))


if __name__ == "__main__":
    unittest.main()
