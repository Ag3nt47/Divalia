"""Async, explicitly configured collectors with durable local deduplication.

Each configured URL is one bounded request: no redirects, proxy environment,
discovery, reference-link retrieval or implicit pagination. HTTPS connections pin
public DNS answers and verify the original hostname with the platform trust store.
"""

from __future__ import annotations

import asyncio
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import hashlib
import http.client
import ipaddress
import json
import logging
import math
import os
from pathlib import Path
import re
import socket
import sqlite3
import ssl
import threading
import time
from typing import Any, Awaitable, Callable, Iterable, Mapping
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET

from defusedxml import ElementTree as SafeET
from defusedxml.common import DefusedXmlException

from .models import ThreatBriefing
from .sanitizer import find_cves, normalize_content, sanitize_text, sanitize_url


LOGGER = logging.getLogger(__name__)
Fetcher = Callable[[str, Mapping[str, str]], Awaitable[bytes]]
_KINDS = {
    "rss",
    "atom",
    "kev",
    "cisa_kev",
    "github",
    "github_advisories",
    "nvd",
    "mastodon",
    "social",
}
_STOPWORDS = frozenset(
    "a an and are as at be been by can for from has have in into is it its of on or that the this to was were will with".split()
)
_URL = re.compile(r"https://[^\s<>\"']+")


class FeedError(RuntimeError):
    """A configured source failed transport or format validation."""


@dataclass(frozen=True, slots=True)
class FeedConfig:
    kind: str
    url: str
    credibility: float = 0.5
    token_env: str | None = None

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> FeedConfig:
        raw_url = value.get("url")
        url = sanitize_url(raw_url, allow_tracking=True)
        kind = value.get("kind")
        credibility = value.get("credibility", 0.5)
        token_env = value.get("token_env")
        if kind not in _KINDS:
            raise ValueError(f"Unsupported feed kind: {kind!r}")
        if url is None:
            raise ValueError("Feed URL must be a credential-free public HTTPS URL")
        if (
            isinstance(credibility, bool)
            or not isinstance(credibility, (int, float))
            or not math.isfinite(credibility)
            or not 0 <= credibility <= 1
        ):
            raise ValueError("Feed credibility must be a finite number in [0, 1]")
        if token_env is not None and (
            not isinstance(token_env, str) or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", token_env)
        ):
            raise ValueError("token_env must be an environment-variable name")
        return cls(kind, url, float(credibility), token_env)


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect only to addresses already checked; preserve hostname TLS checks."""

    def __init__(
        self, host: str, port: int, addresses: list[tuple[Any, ...]], deadline: float
    ) -> None:
        super().__init__(
            host,
            port=port,
            timeout=max(0.1, deadline - time.monotonic()),
            context=ssl.create_default_context(),
        )
        self._addresses = addresses
        self._deadline = deadline
        self.transport_socket: ssl.SSLSocket | None = None

    def connect(self) -> None:
        last_error: OSError | None = None
        for family, socktype, proto, _, sockaddr in self._addresses:
            remaining = self._deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Feed connection exceeded deadline")
            raw = socket.socket(family, socktype, proto)
            try:
                raw.settimeout(remaining)
                raw.connect(sockaddr)
                raw.settimeout(max(0.001, self._deadline - time.monotonic()))
                self.sock = self._context.wrap_socket(raw, server_hostname=self.host)
                self.transport_socket = self.sock
                return
            except OSError as error:
                last_error = error
                raw.close()
        raise FeedError("No validated HTTPS address was reachable") from last_error


def _public_addresses(host: str, port: int) -> list[tuple[Any, ...]]:
    addresses = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
    if not addresses:
        raise FeedError("Feed hostname resolved to no addresses")
    # Fail the entire answer if any destination is private; do not pick around a
    # mixed public/private DNS answer. Pinning prevents a second DNS resolution.
    for _, _, _, _, sockaddr in addresses:
        address = ipaddress.ip_address(sockaddr[0])
        if not address.is_global or (
            isinstance(address, ipaddress.IPv6Address)
            and address.ipv4_mapped
            and not address.ipv4_mapped.is_global
        ):
            raise FeedError("Feed resolved to a non-public address")
    return addresses


def _download(url: str, headers: Mapping[str, str], timeout: float, max_bytes: int) -> bytes:
    if sanitize_url(url, allow_tracking=True) != url:
        raise FeedError("Feed URL failed transport validation")
    parsed = urlsplit(url)
    assert parsed.hostname is not None
    deadline = time.monotonic() + timeout
    port = parsed.port or 443
    addresses = _public_addresses(parsed.hostname, port)
    connection = _PinnedHTTPSConnection(parsed.hostname, port, addresses, deadline)

    def abort_transport() -> None:
        # HTTP header parsers can otherwise exceed a socket timeout when a peer
        # trickles one byte at a time. Closing the pinned socket enforces a wall
        # deadline across headers and body, including file wrappers retaining it.
        transport = connection.transport_socket
        if transport is not None:
            try:
                transport.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        connection.close()

    watchdog = threading.Timer(max(0.001, deadline - time.monotonic()), abort_transport)
    watchdog.daemon = True
    watchdog.start()
    target = parsed.path or "/"
    if parsed.query:
        target += "?" + parsed.query
    try:
        connection.request(
            "GET", target, headers={**headers, "Accept-Encoding": "identity", "Connection": "close"}
        )
        response = connection.getresponse()
        if 300 <= response.status <= 399:
            raise FeedError("Feed redirects are disabled; configure the final HTTPS URL")
        if response.status != 200:
            raise FeedError(f"Feed returned HTTP {response.status}")
        if response.getheader("Content-Encoding", "identity").lower() not in {"", "identity"}:
            raise FeedError("Compressed feed responses are disabled")
        length = response.getheader("Content-Length")
        if length is not None:
            try:
                if not 0 <= int(length) <= max_bytes:
                    raise FeedError("Feed response exceeds size limit")
            except ValueError as error:
                raise FeedError("Invalid feed Content-Length") from error
        content = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("Feed response exceeded deadline")
            if connection.transport_socket is not None:
                connection.transport_socket.settimeout(remaining)
            chunk = response.read1(min(65_536, max_bytes + 1 - len(content)))
            if not chunk:
                return bytes(content)
            content.extend(chunk)
            if len(content) > max_bytes:
                raise FeedError("Feed response exceeds size limit")
    finally:
        watchdog.cancel()
        connection.close()


def _date(value: object) -> str | None:
    if not isinstance(value, str) or len(value) > 128:
        return None
    try:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            parsed = parsedate_to_datetime(value)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except (ValueError, TypeError, OverflowError):
        return None


def _dicts(value: object) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _strings(value: object) -> list[str]:
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def _xml_text(element: ET.Element | None) -> str:
    if element is None:
        return ""
    # Preserve nested HTML for the sanitizer, including script/style elements.
    return (element.text or "") + "".join(
        ET.tostring(child, encoding="unicode") for child in element
    )


def _xml_child(element: ET.Element, *names: str) -> ET.Element | None:
    for name in names:
        for child in element:
            if child.tag.rsplit("}", 1)[-1] == name:
                return child
    return None


def _features(text: str) -> tuple[list[str], dict[str, float]]:
    counts = Counter(
        token
        for token in re.findall(r"[a-z0-9][a-z0-9_.-]{1,63}", normalize_content(text))
        if token not in _STOPWORDS
    )
    # Deterministic feature hashing needs no model download or external service.
    vector: dict[str, float] = {}
    for token, count in counts.most_common(2048):
        index = str(
            int.from_bytes(hashlib.blake2s(token.encode(), digest_size=2).digest(), "big") % 512
        )
        vector[index] = vector.get(index, 0.0) + 1.0 + math.log(count)
    magnitude = math.sqrt(sum(value * value for value in vector.values())) or 1.0
    return sorted(counts)[:2048], {index: value / magnitude for index, value in vector.items()}


def _similar(
    tokens: list[str],
    vector: dict[str, float],
    other_tokens: list[str],
    other_vector: dict[str, float],
) -> bool:
    if len(tokens) < 8 or len(other_tokens) < 8:
        return False
    left, right = set(tokens), set(other_tokens)
    # A lexical check guards against embedding hash collisions and very short text.
    if len(left & right) / max(1, len(left | right)) < 0.80:
        return False
    return sum(value * other_vector.get(index, 0.0) for index, value in vector.items()) >= 0.95


class IngestionEngine:
    """Collect normalized, previously unseen claims from an explicit feed list.

    Inject ``async fetcher(url, headers) -> bytes`` for offline tests. Supplied
    fetchers are trusted transport implementations; URL and payload checks remain
    active. SQLite persists exact hashes, CVE sets and bounded local embeddings.
    """

    def __init__(
        self,
        feeds: Iterable[Mapping[str, Any] | FeedConfig],
        state_dir: str | Path,
        *,
        fetcher: Fetcher | None = None,
        max_items_per_feed: int = 200,
        fetch_timeout: float = 20.0,
        max_response_bytes: int = 2_097_152,
        concurrency: int = 4,
    ) -> None:
        if (
            isinstance(max_items_per_feed, bool)
            or not isinstance(max_items_per_feed, int)
            or not 1 <= max_items_per_feed <= 2000
        ):
            raise ValueError("max_items_per_feed must be an integer in [1, 2000]")
        if (
            not isinstance(fetch_timeout, (int, float))
            or not math.isfinite(fetch_timeout)
            or not 0.1 <= fetch_timeout <= 120
        ):
            raise ValueError("fetch_timeout must be in [0.1, 120] seconds")
        if (
            isinstance(max_response_bytes, bool)
            or not isinstance(max_response_bytes, int)
            or not 1024 <= max_response_bytes <= 16_777_216
        ):
            raise ValueError("max_response_bytes must be in [1024, 16777216]")
        if (
            isinstance(concurrency, bool)
            or not isinstance(concurrency, int)
            or not 1 <= concurrency <= 8
        ):
            raise ValueError("concurrency must be an integer in [1, 8]")
        self.feeds = tuple(
            FeedConfig.from_dict(
                {
                    "kind": feed.kind,
                    "url": feed.url,
                    "credibility": feed.credibility,
                    "token_env": feed.token_env,
                }
            )
            if isinstance(feed, FeedConfig)
            else FeedConfig.from_dict(feed)
            for feed in feeds
        )
        if len(self.feeds) > 64:
            raise ValueError("At most 64 explicitly configured feeds are supported")
        self.max_items_per_feed = max_items_per_feed
        self.fetch_timeout = float(fetch_timeout)
        self.max_response_bytes = max_response_bytes
        self._fetcher = fetcher
        self._concurrency = concurrency
        self._closed = False
        self._ingest_lock = asyncio.Lock()
        directory = Path(state_dir).expanduser().absolute()
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        database = directory / "intelligence.sqlite3"
        if database.is_symlink():
            raise ValueError("Intelligence database must not be a symbolic link")
        self._database = sqlite3.connect(database, timeout=5)
        self._database.execute("PRAGMA foreign_keys=ON")
        self._database.execute("PRAGMA journal_mode=WAL")
        self._database.execute("PRAGMA synchronous=FULL")
        self._database.executescript("""
            BEGIN;
            CREATE TABLE IF NOT EXISTS briefings (
                id TEXT PRIMARY KEY,
                content_hash TEXT NOT NULL UNIQUE,
                data TEXT NOT NULL,
                tokens TEXT NOT NULL,
                vector TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS briefing_cves (
                briefing_id TEXT NOT NULL REFERENCES briefings(id) ON DELETE CASCADE,
                cve TEXT NOT NULL,
                PRIMARY KEY (briefing_id, cve)
            );
            CREATE INDEX IF NOT EXISTS cve_lookup ON briefing_cves(cve);
            CREATE TABLE IF NOT EXISTS briefing_cve_sets (
                signature TEXT PRIMARY KEY,
                briefing_id TEXT NOT NULL UNIQUE REFERENCES briefings(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS reporting_sources (
                briefing_id TEXT NOT NULL REFERENCES briefings(id) ON DELETE CASCADE,
                host TEXT NOT NULL,
                PRIMARY KEY (briefing_id, host)
            );
            COMMIT;
        """)
        self._database.commit()

    async def ingest(self) -> list[ThreatBriefing]:
        """Return only new briefings; isolate failed feeds and persist before return."""
        async with self._ingest_lock:
            if self._closed:
                raise RuntimeError("Ingestion engine is closed")
            semaphore = asyncio.Semaphore(self._concurrency)

            async def collect(feed: FeedConfig) -> tuple[FeedConfig, list[ThreatBriefing]]:
                async with semaphore:
                    try:
                        content = await self._fetch(feed)
                        return feed, self._parse(feed, content)
                    except Exception as error:
                        # Do not include tokens, untrusted response bodies or URL
                        # queries in logs. Cancellation still propagates.
                        LOGGER.warning(
                            "Feed %s (%s) failed: %s",
                            urlsplit(feed.url).hostname,
                            feed.kind,
                            type(error).__name__,
                        )
                        return feed, []

            results = await asyncio.gather(*(collect(feed) for feed in self.feeds))
            new_ids: list[str] = []
            with self._database:
                for feed, briefings in results:
                    for briefing in briefings:
                        if self._remember(briefing, feed.url):
                            new_ids.append(briefing.id)
            # Later sources in this batch may add cross-reporting metadata.
            return [
                ThreatBriefing.from_dict(
                    json.loads(
                        self._database.execute(
                            "SELECT data FROM briefings WHERE id=?", (identifier,)
                        ).fetchone()[0]
                    )
                )
                for identifier in new_ids
            ]

    async def _fetch(self, feed: FeedConfig) -> bytes:
        headers = {
            "User-Agent": "Divalia/2.0 (defensive threat-intelligence ingestion)",
            "Accept": "application/json, application/atom+xml, application/rss+xml, application/xml, text/xml",
        }
        if feed.token_env:
            token = os.environ.get(feed.token_env, "")
            if not token:
                raise FeedError("Configured source token is missing")
            if len(token) > 8192 or any(ord(char) < 33 or ord(char) > 126 for char in token):
                raise FeedError("Configured source token has an invalid format")
            if feed.kind == "nvd":
                headers["apiKey"] = token
            else:
                headers["Authorization"] = "Bearer " + token
        async with asyncio.timeout(self.fetch_timeout):
            if self._fetcher is not None:
                content = await self._fetcher(feed.url, headers)
            else:
                content = await asyncio.to_thread(
                    _download, feed.url, headers, self.fetch_timeout, self.max_response_bytes
                )
        if not isinstance(content, bytes):
            raise FeedError("Fetcher must return bytes")
        if len(content) > self.max_response_bytes:
            raise FeedError("Feed response exceeds size limit")
        return content

    def _briefing(
        self,
        feed: FeedConfig,
        title: object,
        summary: object,
        url: object,
        date: object = None,
        references: Iterable[object] = (),
        identifiers: Iterable[object] = (),
    ) -> ThreatBriefing | None:
        cleaned_title = sanitize_text(title, max_length=500)
        cleaned_summary = sanitize_text(summary)
        if not cleaned_title:
            return None
        source_url = sanitize_url(url) or sanitize_url(feed.url)
        assert source_url is not None
        links = tuple(dict.fromkeys(link for value in references if (link := sanitize_url(value))))[
            :32
        ]
        cves = find_cves(cleaned_title, cleaned_summary, *identifiers)
        digest = hashlib.sha256(
            (
                source_url
                + "\0"
                + normalize_content(cleaned_title + " " + cleaned_summary)
                + "\0"
                + ",".join(cves)
            ).encode()
        ).hexdigest()
        return ThreatBriefing(
            digest,
            cleaned_title,
            cleaned_summary,
            source_url,
            feed.kind,
            cves,
            _date(date),
            feed.credibility,
            links,
        )

    def _parse(self, feed: FeedConfig, content: bytes) -> list[ThreatBriefing]:
        if feed.kind in {"rss", "atom"}:
            return self._parse_xml(feed, content)
        try:
            data = json.loads(content.decode("utf-8-sig"))
        except (ValueError, UnicodeError, RecursionError) as error:
            raise FeedError("Source did not return valid UTF-8 JSON") from error
        results: list[ThreatBriefing] = []

        def add(*args: Any, **kwargs: Any) -> None:
            briefing = self._briefing(feed, *args, **kwargs)
            if briefing is not None:
                results.append(briefing)

        if feed.kind in {"kev", "cisa_kev"}:
            if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
                raise FeedError("Expected CISA KEV vulnerabilities array")
            records = sorted(
                _dicts(data["vulnerabilities"]),
                key=lambda item: str(item.get("dateAdded", "")),
                reverse=True,
            )
            for item in records[: self.max_items_per_feed]:
                cve = item.get("cveID", "")
                notes = item.get("notes", "")
                references = _URL.findall(notes) if isinstance(notes, str) else []
                references.extend(
                    f"https://www.cve.org/CVERecord?id={identifier}"
                    for identifier in find_cves(cve)
                )
                summary = "\n".join(
                    value
                    for value in (item.get("shortDescription"), item.get("requiredAction"))
                    if isinstance(value, str)
                )
                add(
                    item.get("vulnerabilityName") or cve,
                    summary,
                    feed.url,
                    item.get("dateAdded"),
                    references,
                    (cve,),
                )
        elif feed.kind in {"github", "github_advisories"}:
            if not isinstance(data, list):
                raise FeedError("Expected GitHub advisory array")
            for item in _dicts(data)[: self.max_items_per_feed]:
                if item.get("withdrawn_at"):
                    continue
                identifiers = [entry.get("value", "") for entry in _dicts(item.get("identifiers"))]
                references = (
                    [
                        entry.get("url", "") if isinstance(entry, dict) else entry
                        for entry in item.get("references", [])
                    ]
                    if isinstance(item.get("references", []), list)
                    else []
                )
                add(
                    item.get("summary"),
                    item.get("description", ""),
                    item.get("html_url"),
                    item.get("published_at"),
                    references,
                    [item.get("cve_id", ""), *identifiers],
                )
        elif feed.kind == "nvd":
            if not isinstance(data, dict) or not isinstance(data.get("vulnerabilities"), list):
                raise FeedError("Expected NVD 2.0 vulnerabilities array")
            for entry in _dicts(data["vulnerabilities"])[: self.max_items_per_feed]:
                item = entry.get("cve")
                if not isinstance(item, dict) or item.get("vulnStatus") == "Rejected":
                    continue
                descriptions = _dicts(item.get("descriptions"))
                description = next(
                    (item.get("value", "") for item in descriptions if item.get("lang") == "en"), ""
                )
                cve = item.get("id", "")
                references = [entry.get("url", "") for entry in _dicts(item.get("references"))]
                source_url = (
                    f"https://nvd.nist.gov/vuln/detail/{cve}" if find_cves(cve) else feed.url
                )
                add(cve, description, source_url, item.get("published"), references, (cve,))
        elif feed.kind in {"mastodon", "social"}:
            if not isinstance(data, list):
                raise FeedError("Expected curated Mastodon status array")
            for item in _dicts(data)[: self.max_items_per_feed]:
                # Boosts are deliberately not recursively trusted or fetched.
                text = sanitize_text(item.get("content", ""))
                references = [
                    entry.get("url", "") for entry in _dicts(item.get("media_attachments"))
                ]
                card = item.get("card")
                if isinstance(card, dict):
                    references.append(card.get("url", ""))
                references.extend(_URL.findall(text))
                add(
                    text[:160],
                    text,
                    item.get("url") or item.get("uri"),
                    item.get("created_at"),
                    references,
                )
        return results

    def _parse_xml(self, feed: FeedConfig, content: bytes) -> list[ThreatBriefing]:
        try:
            text = content.decode("utf-8-sig")
            if "\x00" in text or re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, re.IGNORECASE):
                raise FeedError("XML declarations and entities are prohibited")
            root = SafeET.fromstring(
                text, forbid_dtd=True, forbid_entities=True, forbid_external=True
            )
        except (ET.ParseError, DefusedXmlException, UnicodeError, RecursionError) as error:
            raise FeedError("Source did not return safe UTF-8 RSS/Atom XML") from error
        elements = list(root.iter())
        if len(elements) > 20_000:
            raise FeedError("XML feed exceeds element limit")
        entries = [
            element for element in elements if element.tag.rsplit("}", 1)[-1] in {"item", "entry"}
        ]
        if root.tag.rsplit("}", 1)[-1] not in {"rss", "feed", "RDF"}:
            raise FeedError("Expected an RSS or Atom document")
        results: list[ThreatBriefing] = []
        for entry in entries[: self.max_items_per_feed]:
            url: object = None
            for child in entry:
                if child.tag.rsplit("}", 1)[-1] == "link":
                    if child.attrib.get("rel", "alternate") == "alternate":
                        candidate = child.attrib.get("href") or child.text
                        if sanitize_url(candidate):
                            url = candidate
                            break
            title = _xml_text(_xml_child(entry, "title"))
            summary = _xml_text(_xml_child(entry, "encoded", "content", "description", "summary"))
            date = _xml_text(_xml_child(entry, "published", "pubDate", "date", "updated"))
            references = _URL.findall(summary)
            briefing = self._briefing(feed, title, summary, url, date, references)
            if briefing is not None:
                results.append(briefing)
        return results

    def _remember(self, briefing: ThreatBriefing, feed_url: str) -> bool:
        content = normalize_content(briefing.title + " " + briefing.summary)
        digest = hashlib.sha256((content + "\0" + ",".join(briefing.cves)).encode()).hexdigest()
        tokens, vector = _features(content)
        row = self._database.execute(
            "SELECT id,data FROM briefings WHERE content_hash=?", (digest,)
        ).fetchone()
        if row is None and briefing.cves:
            # Exact indexed CVE sets capture overlaps without losing a distinct
            # CVE in a multi-vulnerability article, even across old history.
            row = self._database.execute(
                "SELECT b.id,b.data FROM briefings b JOIN briefing_cve_sets c ON b.id=c.briefing_id WHERE c.signature=?",
                (",".join(briefing.cves),),
            ).fetchone()
        if row is None and not briefing.cves:
            candidates = self._database.execute(
                "SELECT id,data,tokens,vector FROM briefings WHERE NOT EXISTS (SELECT 1 FROM briefing_cves c WHERE c.briefing_id=briefings.id) ORDER BY rowid DESC LIMIT 1000"
            ).fetchall()
            row = next(
                (
                    (candidate[0], candidate[1])
                    for candidate in candidates
                    if _similar(tokens, vector, json.loads(candidate[2]), json.loads(candidate[3]))
                ),
                None,
            )
        host = urlsplit(feed_url).hostname or ""
        if row is not None:
            identifier, data = row
            previous = ThreatBriefing.from_dict(json.loads(data))
            hosts = {
                item[0]
                for item in self._database.execute(
                    "SELECT host FROM reporting_sources WHERE briefing_id=?", (identifier,)
                )
            }
            if len(hosts) < 32:
                self._database.execute(
                    "INSERT OR IGNORE INTO reporting_sources VALUES (?,?)", (identifier, host)
                )
                hosts.add(host)
            references = tuple(
                dict.fromkeys(
                    (
                        *previous.evidence_urls,
                        previous.source_url,
                        briefing.source_url,
                        *briefing.evidence_urls,
                    )
                )
            )[:64]
            previous = replace(
                previous,
                evidence_urls=references,
                credibility=max(previous.credibility, briefing.credibility),
                corroboration="cross_reported" if len(hosts) > 1 else "unverified",
            )
            self._database.execute(
                "UPDATE briefings SET data=? WHERE id=?",
                (json.dumps(previous.to_dict(), ensure_ascii=False), identifier),
            )
            return False
        self._database.execute(
            "INSERT INTO briefings VALUES (?,?,?,?,?,?)",
            (
                briefing.id,
                digest,
                json.dumps(briefing.to_dict(), ensure_ascii=False),
                json.dumps(tokens),
                json.dumps(vector),
                datetime.now(timezone.utc).isoformat(),
            ),
        )
        self._database.executemany(
            "INSERT INTO briefing_cves VALUES (?,?)", ((briefing.id, cve) for cve in briefing.cves)
        )
        if briefing.cves:
            self._database.execute(
                "INSERT INTO briefing_cve_sets VALUES (?,?)", (",".join(briefing.cves), briefing.id)
            )
        self._database.execute("INSERT INTO reporting_sources VALUES (?,?)", (briefing.id, host))
        return True

    def close(self) -> None:
        if not self._closed:
            self._database.close()
            self._closed = True

    def __enter__(self) -> IngestionEngine:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
