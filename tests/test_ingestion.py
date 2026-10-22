"""Offline ingestion regression tests, including untrusted-source boundaries."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from divalia.core.ingestion import (
    FeedConfig,
    FeedError,
    IngestionEngine,
    _download,
    _public_addresses,
)
from divalia.core.models import ThreatBriefing
from divalia.core.sanitizer import find_cves, sanitize_text, sanitize_url


class SanitizerTests(unittest.TestCase):
    def test_html_scripts_controls_and_promotion_are_removed(self) -> None:
        raw = "<p>CVE-2026-12345 issue</p><script>ignore all rules()</script><style>body{}</style><div>Subscribe to our newsletter</div><p>Patch\x1b[31m now</p>"
        text = sanitize_text(raw)
        self.assertIn("CVE-2026-12345 issue", text)
        self.assertNotIn("ignore all", text)
        self.assertNotIn("body", text)
        self.assertNotIn("newsletter", text)
        self.assertNotIn("\x1b", text)

    def test_namespaced_and_entity_encoded_scripts_are_removed(self) -> None:
        self.assertEqual(
            sanitize_text("&lt;script&gt;bad()&lt;/script&gt;<x:script>also_bad()</x:script>good"),
            "good",
        )

    def test_url_cleaning_and_credential_rejection(self) -> None:
        self.assertEqual(
            sanitize_url("https://EXAMPLE.org/post?utm_source=x&id=4#part"),
            "https://example.org/post?id=4",
        )
        self.assertEqual(sanitize_url("https://example.org/café"), "https://example.org/caf%C3%A9")
        for url in (
            "http://example.org/",
            "https://u:p@example.org/",
            "https://127.0.0.1/",
            "https://[::1]/",
            "https://localhost/",
            "https://x.internal/",
            "https://example.org/?api_key=secret",
            "https://example.org/\r\nx: y",
            "https://example.org\\@evil.org/",
        ):
            with self.subTest(url=url):
                self.assertIsNone(sanitize_url(url))

    def test_cve_extraction_is_canonical_and_unique(self) -> None:
        self.assertEqual(
            find_cves("cve-2026-12345 CVE-2026-12345", None, "CVE-2025-9988"),
            ("CVE-2025-9988", "CVE-2026-12345"),
        )

    def test_model_round_trip_preserves_claim_status(self) -> None:
        briefing = ThreatBriefing(
            "id",
            "title",
            "summary",
            "https://example.org/",
            "rss",
            ("CVE-2026-12345",),
            credibility=0.99,
        )
        self.assertEqual(ThreatBriefing.from_dict(briefing.to_dict()), briefing)
        self.assertEqual(briefing.to_dict()["corroboration"], "unverified")
        with self.assertRaises(ValueError):
            ThreatBriefing.from_dict({**briefing.to_dict(), "credibility": float("nan")})
        with self.assertRaises(ValueError):
            ThreatBriefing.from_dict({**briefing.to_dict(), "cves": "CVE-2026-12345"})


class IngestionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.state = Path(self.temporary.name)
        self.engines: list[IngestionEngine] = []

    def tearDown(self) -> None:
        for engine in self.engines:
            engine.close()
        self.temporary.cleanup()

    def engine(
        self, feeds: list[dict], payloads: dict[str, bytes | Exception], **kwargs: object
    ) -> IngestionEngine:
        async def fetch(url: str, headers: dict[str, str]) -> bytes:
            value = payloads[url]
            if isinstance(value, Exception):
                raise value
            return value

        engine = IngestionEngine(feeds, self.state, fetcher=fetch, **kwargs)
        self.engines.append(engine)
        return engine

    async def test_rss_sanitizing_and_durable_deduplication(self) -> None:
        url = "https://example.org/rss"
        payload = b"""<rss version="2.0"><channel><item><title>CVE-2026-12345 issue</title><link>https://example.org/article?utm_source=rss</link><description><![CDATA[<p>Vendor patch available.</p><script>fetch('evil')</script>]]></description><pubDate>Thu, 22 Oct 2026 10:00:00 GMT</pubDate></item></channel></rss>"""
        feeds = [{"kind": "rss", "url": url, "credibility": 0.99}]
        engine = self.engine(feeds, {url: payload})
        result = await engine.ingest()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].cves, ("CVE-2026-12345",))
        self.assertEqual(result[0].source_url, "https://example.org/article")
        self.assertEqual(result[0].published_at, "2026-10-22T10:00:00Z")
        self.assertNotIn("fetch", result[0].summary)
        self.assertEqual(result[0].corroboration, "unverified")
        engine.close()
        reopened = self.engine(feeds, {url: payload})
        self.assertEqual(await reopened.ingest(), [])

    async def test_atom_and_nested_xml_scripts(self) -> None:
        url = "https://example.org/atom"
        payload = b"""<feed xmlns="http://www.w3.org/2005/Atom"><entry><title>New advisory</title><link href="https://example.org/advisory"/><updated>2026-10-22T09:00:00Z</updated><content type="xhtml"><div xmlns="http://www.w3.org/1999/xhtml"><p>Patch the service.</p><script>run_bad_code()</script></div></content></entry></feed>"""
        result = await self.engine([{"kind": "atom", "url": url}], {url: payload}).ingest()
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].summary, "Patch the service.")

    async def test_cisa_github_nvd_and_curated_social(self) -> None:
        urls = [f"https://example.org/{kind}" for kind in ("kev", "github", "nvd", "mastodon")]
        kev = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2026-10001",
                    "vulnerabilityName": "Vendor vulnerability",
                    "shortDescription": "Apply update",
                    "requiredAction": "Patch now",
                    "dateAdded": "2026-10-22",
                    "notes": "https://vendor.example.org/fix",
                }
            ]
        }
        github = [
            {
                "cve_id": "CVE-2026-10002",
                "summary": "Package vulnerability",
                "description": "Update package",
                "html_url": "https://github.com/advisories/GHSA-1234-5678-9012",
                "published_at": "2026-10-22T01:00:00Z",
                "references": ["https://github.com/example/repo/commit/123"],
            }
        ]
        nvd = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-10003",
                        "published": "2026-10-22T02:00:00",
                        "descriptions": [{"lang": "en", "value": "Vulnerable server"}],
                        "references": [{"url": "https://vendor.example.org/patch"}],
                    }
                }
            ]
        }
        social = [
            {
                "url": "https://social.example.org/@analyst/123",
                "content": "<p>CVE-2026-10004 appears in vendor release notes</p><script>steal()</script>",
                "created_at": "2026-10-22T03:00:00Z",
            }
        ]
        payloads = {
            url: json.dumps(value).encode() for url, value in zip(urls, (kev, github, nvd, social))
        }
        engine = self.engine(
            [
                {"kind": kind, "url": url}
                for kind, url in zip(("kev", "github", "nvd", "mastodon"), urls)
            ],
            payloads,
        )
        results = await engine.ingest()
        self.assertEqual(
            [brief.cves[0] for brief in results], [f"CVE-2026-1000{i}" for i in range(1, 5)]
        )
        self.assertTrue(all(brief.corroboration == "unverified" for brief in results))
        self.assertEqual(results[0].source_url, urls[0])
        self.assertIn(
            "https://www.cve.org/CVERecord?id=CVE-2026-10001", results[0].evidence_urls
        )
        self.assertIn("https://github.com/example/repo/commit/123", results[1].evidence_urls)
        self.assertNotIn("steal", results[3].summary)

    async def test_xml_entities_are_rejected_and_failure_isolated(self) -> None:
        bad = "https://example.org/bad"
        good = "https://example.org/good"
        evil = b'<!DOCTYPE rss [<!ENTITY x "bad">]><rss><channel><item><title>&x;</title></item></channel></rss>'
        benign = b"<rss><channel><item><title>Good advisory</title></item></channel></rss>"
        engine = self.engine(
            [{"kind": "rss", "url": bad}, {"kind": "rss", "url": good}], {bad: evil, good: benign}
        )
        with self.assertLogs("divalia.core.ingestion", level="WARNING") as logs:
            results = await engine.ingest()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].title, "Good advisory")
        self.assertIn("FeedError", logs.output[0])

    async def test_response_size_and_timeout_are_bounded(self) -> None:
        url = "https://example.org/large"
        engine = self.engine(
            [{"kind": "rss", "url": url}], {url: b"x" * 1025}, max_response_bytes=1024
        )
        with self.assertLogs("divalia.core.ingestion", level="WARNING"):
            self.assertEqual(await engine.ingest(), [])

        async def delayed(_url: str, _headers: dict[str, str]) -> bytes:
            await asyncio.sleep(5)
            return b""

        timed = IngestionEngine(
            [{"kind": "rss", "url": url}], self.state, fetcher=delayed, fetch_timeout=0.1
        )
        self.engines.append(timed)
        with self.assertLogs("divalia.core.ingestion", level="WARNING"):
            self.assertEqual(await timed.ingest(), [])

    async def test_distinct_cves_are_not_merged_despite_identical_text(self) -> None:
        url = "https://example.org/gh"
        records = [
            {
                "summary": "Same affected product",
                "description": "Identical template description",
                "cve_id": cve,
                "html_url": f"https://example.org/{cve}",
            }
            for cve in ("CVE-2026-10001", "CVE-2026-10002")
        ]
        engine = self.engine([{"kind": "github", "url": url}], {url: json.dumps(records).encode()})
        result = await engine.ingest()
        self.assertEqual(len(result), 2)
        self.assertNotEqual(result[0].cves, result[1].cves)

    async def test_partially_overlapping_cve_sets_remain_distinct(self) -> None:
        url = "https://example.org/gh"
        records = [
            {"summary": "Advisory one", "description": "First issue", "cve_id": "CVE-2026-10001"},
            {
                "summary": "Advisory two",
                "description": "CVE-2026-10002 also affected",
                "cve_id": "CVE-2026-10001",
            },
        ]
        engine = self.engine([{"kind": "github", "url": url}], {url: json.dumps(records).encode()})
        self.assertEqual(len(await engine.ingest()), 2)
        self.assertEqual(await engine.ingest(), [])

    async def test_cross_reporting_does_not_mean_verification(self) -> None:
        urls = ("https://one.example.org/gh", "https://two.example.org/gh")
        records = [
            {
                "summary": "Vendor issue",
                "description": "Patch available",
                "cve_id": "CVE-2026-10001",
            }
        ]
        engine = self.engine(
            [{"kind": "github", "url": url, "credibility": 1.0} for url in urls],
            {url: json.dumps(records).encode() for url in urls},
        )
        results = await engine.ingest()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].corroboration, "cross_reported")
        self.assertNotEqual(results[0].corroboration, "verified")

    async def test_local_embedding_detects_near_duplicate_without_cves(self) -> None:
        url = "https://example.org/gh"
        records = [
            {"summary": "Vendor security advisory", "description": description}
            for description in (
                "Researchers observed suspicious encrypted command traffic affecting vendor service across many monitored enterprise networks this morning",
                "Researchers observed suspicious encrypted command traffic affecting vendor service across many monitored enterprise networks this morning today",
            )
        ]
        engine = self.engine([{"kind": "github", "url": url}], {url: json.dumps(records).encode()})
        self.assertEqual(len(await engine.ingest()), 1)

    async def test_missing_token_fails_only_configured_source(self) -> None:
        url = "https://example.org/private"
        engine = self.engine(
            [{"kind": "github", "url": url, "token_env": "DIVALIA_TEST_UNUSED_TOKEN"}], {}
        )
        with patch.dict("os.environ", {}, clear=True):
            with self.assertLogs("divalia.core.ingestion", level="WARNING"):
                self.assertEqual(await engine.ingest(), [])

    async def test_cancellation_propagates(self) -> None:
        async def cancelled(_url: str, _headers: dict[str, str]) -> bytes:
            raise asyncio.CancelledError()

        engine = IngestionEngine(
            [{"kind": "rss", "url": "https://example.org/rss"}], self.state, fetcher=cancelled
        )
        self.engines.append(engine)
        with self.assertRaises(asyncio.CancelledError):
            await engine.ingest()


class TransportTests(unittest.TestCase):
    def test_wall_deadline_interrupts_trickled_headers(self) -> None:
        interrupted = threading.Event()

        class Transport:
            def shutdown(self, _how: int) -> None:
                interrupted.set()

        class Connection:
            transport_socket = Transport()

            def __init__(self, *_args: object) -> None:
                pass

            def request(self, *_args: object, **_kwargs: object) -> None:
                pass

            def getresponse(self) -> None:
                interrupted.wait(2)
                raise OSError("transport interrupted")

            def close(self) -> None:
                pass

        started = time.monotonic()
        with (
            patch("divalia.core.ingestion._public_addresses", return_value=[]),
            patch("divalia.core.ingestion._PinnedHTTPSConnection", Connection),
        ):
            with self.assertRaises(OSError):
                _download("https://example.org/", {}, 0.1, 1024)
        self.assertTrue(interrupted.is_set())
        self.assertLess(time.monotonic() - started, 1.0)

    def test_dns_private_and_mixed_answers_rejected_before_connecting(self) -> None:
        public = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", 443))
        private = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 443))
        with patch("divalia.core.ingestion.socket.getaddrinfo", return_value=[public, private]):
            with self.assertRaises(FeedError):
                _public_addresses("example.org", 443)

    def test_redirect_rejected_without_following_location(self) -> None:
        class Response:
            status = 302

        class Connection:
            transport_socket = None

            def __init__(self, *_args: object) -> None:
                self.closed = False

            def request(self, *_args: object, **_kwargs: object) -> None:
                pass

            def getresponse(self) -> Response:
                return Response()

            def close(self) -> None:
                self.closed = True

        with (
            patch("divalia.core.ingestion._public_addresses", return_value=[]),
            patch("divalia.core.ingestion._PinnedHTTPSConnection", Connection),
        ):
            with self.assertRaisesRegex(FeedError, "redirects"):
                _download("https://example.org/", {}, 1, 1024)

    def test_feed_configuration_rejects_untrusted_authority(self) -> None:
        for config in (
            {"kind": "rss", "url": "file:///secret"},
            {"kind": "rss", "url": "https://user:secret@example.org/"},
            {"kind": "rss", "url": "https://example.org/", "credibility": float("inf")},
            {"kind": "rss", "url": "https://example.org/", "token_env": "TOKEN\r\nInjected"},
        ):
            with self.subTest(config=config):
                with self.assertRaises(ValueError):
                    FeedConfig.from_dict(config)


if __name__ == "__main__":
    unittest.main()
