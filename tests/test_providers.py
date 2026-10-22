from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import json
import os
import time
import unittest
from unittest.mock import AsyncMock, patch

from divalia.ai.base_provider import (
    BaseProvider,
    CompatibleProvider,
    ProviderError,
    _NoRedirect,
    create_provider,
    validate_endpoint,
)
from divalia.ai.ollama_provider import OllamaProvider
from divalia.ai.installer import check_runtime
from divalia.ai.remote_provider import RemoteProvider
from divalia.ai.router import ModelRouter


@asynccontextmanager
async def http_server(handler):
    """Real loopback HTTP transport without models, DNS, remote services or threads."""
    pending = set()

    async def connection(reader, writer):
        task = asyncio.current_task()
        pending.add(task)
        try:
            await handler(reader, writer)
        except (ConnectionError, asyncio.IncompleteReadError):
            pass
        finally:
            writer.close()
            pending.discard(task)

    server = await asyncio.start_server(connection, "127.0.0.1", 0)
    endpoint = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
    try:
        yield endpoint
    finally:
        server.close()
        await server.wait_closed()
        for task in pending:
            task.cancel()
        await asyncio.gather(*pending, return_exceptions=True)


async def consume_request(reader):
    headers = await reader.readuntil(b"\r\n\r\n")
    length = next((int(line.split(b":", 1)[1]) for line in headers.split(b"\r\n")
                   if line.lower().startswith(b"content-length:")), 0)
    return headers, await reader.readexactly(length)


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
            "http://127.0.0.1:99999",
            "http://127.0.0.1:0",
            "http://127.0.0.1/\ninjected",
            "http://127.0.0.1/with space",
            "http://127.0.0.1/é",
            [],
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
                tokens = (payload["options"]["num_predict"] if adapter is OllamaProvider
                          else payload["max_tokens"])
                self.assertEqual(tokens, 256)
                await provider.generate("evidence", role="heavy")
                heavy_payload = request.call_args.args[1]
                tokens = (heavy_payload["options"]["num_predict"] if adapter is OllamaProvider
                          else heavy_payload["max_tokens"])
                self.assertEqual(tokens, 4096)

    async def test_invalid_role_and_invalid_output_are_rejected(self):
        provider = OllamaProvider(
            "http://127.0.0.1:11434", light_model="small", heavy_model="large"
        )
        with self.assertRaises(ValueError):
            await provider.generate("data", role="other")
        for response in [{}, {"response": None}, {"response": ""}, {"response": "x" * 100001}, []]:
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
                patch.object(provider, "_request_async", return_value=response) as request,
            ):
                output = await provider.generate("evidence", system="defensive policy")
                self.assertEqual(output, "answer")
                self.assertEqual(request.call_args.args[0], expected_path)
                serialized = json.dumps(request.call_args.args[1])
                self.assertIn("evidence", serialized)
                self.assertNotIn("synthetic-test-token", serialized)
                if kind == "anthropic":
                    self.assertEqual(request.call_args.kwargs["headers"]["x-api-key"],
                                     "synthetic-test-token")
                def output_tokens(payload):
                    if kind == "gemini":
                        return payload["generationConfig"]["maxOutputTokens"]
                    return payload["max_completion_tokens" if kind == "openai" else "max_tokens"]

                self.assertEqual(output_tokens(request.call_args.args[1]), 4096)
                await provider.generate("evidence", role="light")
                self.assertEqual(output_tokens(request.call_args.args[1]), 256)

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
                patch.object(provider, "_request_async", return_value=response),
                self.assertRaises(ProviderError),
            ):
                await provider.generate("evidence")

    async def test_http_transport_ignores_proxy_environment_and_sends_role_request(self):
        captured = []

        async def handler(reader, writer):
            captured.append(await consume_request(reader))
            body = b'{"choices":[{"message":{"content":"answer"}}]}'
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: "
                         + str(len(body)).encode() + b"\r\n\r\n" + body)
            await writer.drain()

        async with http_server(handler) as endpoint:
            provider = CompatibleProvider(endpoint + "/v1", light_model="small",
                                          heavy_model="heavy", key_env="DIVALIA_TEST_CREDENTIAL")
            with patch.dict(os.environ, {"DIVALIA_TEST_CREDENTIAL": "synthetic-test-token",
                                        "http_proxy": "http://127.0.0.1:1"}):
                self.assertEqual(await provider.generate("evidence", role="light"), "answer")
        headers, body = captured[0]
        self.assertTrue(headers.startswith(b"POST /v1/chat/completions HTTP/1.1\r\n"))
        self.assertIn(b"Authorization: Bearer synthetic-test-token\r\n", headers)
        self.assertEqual(json.loads(body)["model"], "small")
        self.assertNotIn(b"synthetic-test-token", body)

    async def test_missing_credential_oversized_response_and_http_error_do_not_echo_secrets(self):
        provider = CompatibleProvider(
            "http://127.0.0.1:1234/v1",
            light_model="small",
            heavy_model="heavy",
            key_env="DIVALIA_TEST_CREDENTIAL",
        )
        with (
            patch.dict(os.environ, {}, clear=True),
            patch("divalia.ai.base_provider.asyncio.open_connection") as connect,
        ):
            with self.assertRaises(ProviderError):
                await provider.request("/chat/completions", {})
            connect.assert_not_called()
        provider.key_env = ""

        responses = [
            b"HTTP/1.1 200 OK\r\nContent-Length: 1048577\r\n\r\n",
            b"HTTP/1.1 429 secret hidden\r\nContent-Length: 13\r\n\r\nsecret hidden",
            b"HTTP/1.1 302 Found\r\nLocation: https://attacker.example\r\n\r\n",
            b"HTTP/1.1 200 OK\r\n\r\n" + b"x" * 1048577,
        ]
        for response in responses:
            async def handler(reader, writer):
                await consume_request(reader)
                writer.write(response)
                await writer.drain()

            async with http_server(handler) as endpoint:
                provider.endpoint = endpoint
                with self.subTest(response=response[:40]), self.assertRaises(ProviderError) as raised:
                    await provider.request("/chat/completions", {})
                self.assertNotIn("hidden", str(raised.exception))
                self.assertNotIn("attacker", str(raised.exception))

    async def test_chunked_json_and_malformed_http_or_json_are_bounded(self):
        responses = [
            (b"Transfer-Encoding: chunked\r\n", b"7\r\n{\"ok\":1\r\n1\r\n}\r\n0\r\n\r\n", {"ok": 1}),
            (b"Content-Length: 8\r\n", b'{"ok":1}', {"ok": 1}),
            (b"", b'{"ok":1}', {"ok": 1}),
            (b"Content-Length: 8\r\nContent-Length: 8\r\n", b'{"ok":1}', None),
            (b"Transfer-Encoding: chunked\r\nContent-Length: 8\r\n", b"", None),
            (b"Transfer-Encoding: gzip\r\n", b"", None),
            (b"Transfer-Encoding: chunked\r\n", b"100001\r\n", None),
            (b"Transfer-Encoding: chunked\r\n", b"junk\r\n", None),
            (b"Content-Length: -1\r\n", b"", None),
            (b"", b'{"value":NaN}', None),
            (b"Content-Length: 100\r\n", b"{}", None),
        ]
        for headers, body, expected in responses:
            async def handler(reader, writer):
                await consume_request(reader)
                writer.write(b"HTTP/1.1 200 OK\r\n" + headers + b"\r\n" + body)
                await writer.drain()

            async with http_server(handler) as endpoint:
                provider = CompatibleProvider(endpoint, light_model="small", heavy_model="heavy")
                with self.subTest(headers=headers, body=body[:30]):
                    if expected is None:
                        with self.assertRaises(ProviderError):
                            await provider.request("/chat/completions", {})
                    else:
                        self.assertEqual(await provider.request("/chat/completions", {}), expected)

    async def test_total_timeout_bounds_header_and_body_drips(self):
        for prefix in [b"HTTP/1.1 200 OK\r\nX-Slow: ", b"HTTP/1.1 200 OK\r\n\r\n"]:
            async def handler(reader, writer):
                await consume_request(reader)
                writer.write(prefix)
                await writer.drain()
                while True:
                    writer.write(b" ")
                    await writer.drain()
                    await asyncio.sleep(0.05)

            async with http_server(handler) as endpoint:
                provider = CompatibleProvider(endpoint, light_model="small", heavy_model="heavy",
                                              timeout=1)
                started = time.monotonic()
                with self.subTest(prefix=prefix), self.assertRaisesRegex(ProviderError, "timeout"):
                    await provider.request("/chat/completions", {})
                self.assertLess(time.monotonic() - started, 2)

    async def test_cancellation_closes_socket_and_allows_next_request(self):
        entered = asyncio.Event()
        closed = asyncio.Event()
        calls = 0

        async def handler(reader, writer):
            nonlocal calls
            calls += 1
            await consume_request(reader)
            if calls == 1:
                entered.set()
                await reader.read()
                closed.set()
            else:
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                await writer.drain()

        async with http_server(handler) as endpoint:
            provider = CompatibleProvider(endpoint, light_model="small", heavy_model="heavy")
            pending = asyncio.create_task(provider.request("/chat/completions", {}))
            await asyncio.wait_for(entered.wait(), 2)
            pending.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await pending
            await asyncio.wait_for(closed.wait(), 2)
            self.assertEqual(await provider.request("/chat/completions", {}), {})

    async def test_credentials_cannot_inject_http_headers(self):
        provider = CompatibleProvider("http://127.0.0.1:1", light_model="small", heavy_model="heavy",
                                      key_env="DIVALIA_TEST_CREDENTIAL")
        with patch.dict(os.environ, {"DIVALIA_TEST_CREDENTIAL": "synthetic\nX-Injected: bad"}), \
                patch("divalia.ai.base_provider.asyncio.open_connection") as connect:
            with self.assertRaises(ProviderError):
                await provider.request("/chat/completions", {})
            connect.assert_not_called()

    async def test_runtime_readiness_checks_configured_role_models(self):
        provider = OllamaProvider("http://127.0.0.1:1", light_model="small", heavy_model="large:7b")
        with patch.object(provider, "status", return_value={"models": [{"name": "small:latest"}] }):
            light = await check_runtime(provider, roles=("light",))
            self.assertTrue(light["ready"])
            self.assertEqual(light["missing_models"], [])
            both = await check_runtime(provider)
            self.assertFalse(both["ready"])
            self.assertTrue(both["engine_ready"])
            self.assertEqual(both["missing_models"], ["large:7b"])
            self.assertIn("--consent", both["message"])

    async def test_runtime_probe_does_not_wait_for_long_inference_timeout(self):
        provider = OllamaProvider("http://127.0.0.1:1", light_model="small", heavy_model="heavy",
                                  timeout=600)
        canceled = asyncio.Event()

        async def unavailable():
            try:
                await asyncio.sleep(60)
            finally:
                canceled.set()

        with patch.object(provider, "status", side_effect=unavailable):
            status = await asyncio.wait_for(check_runtime(provider), 8)
        self.assertFalse(status["ready"])
        self.assertFalse(status["engine_ready"])
        self.assertTrue(canceled.is_set())


if __name__ == "__main__":
    unittest.main()
