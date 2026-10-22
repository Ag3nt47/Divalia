"""Bounded text and URL cleaning for untrusted feed content.

Cleaning removes presentation and terminal-control characters. It does not make
instructions in a feed trustworthy; LLM callers must still treat all text as data.
"""

from __future__ import annotations

from html import unescape
from html.parser import HTMLParser
import ipaddress
import re
import unicodedata
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit


_CVE = re.compile(r"\bCVE-[0-9]{4}-[0-9]{4,19}\b", re.IGNORECASE | re.ASCII)
_CONTROL = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2060-\u206f\ufeff]"
)
_NOISE = re.compile(
    r"^(?:advertisement|sponsored content|subscribe to (?:our|the) newsletter|follow us on social media)[.!\s]*$",
    re.IGNORECASE,
)
_TRACKERS = {"fbclid", "gclid", "mc_cid", "mc_eid", "ref_src", "ref_url"}
_CREDENTIALS = {
    "access_token",
    "api_key",
    "apikey",
    "authorization",
    "auth",
    "password",
    "token",
    "key",
}
_BLOCKED_TAGS = {
    "script",
    "style",
    "template",
    "noscript",
    "svg",
    "math",
    "iframe",
    "object",
    "embed",
}
_BLOCK_TAGS = {
    "p",
    "div",
    "br",
    "li",
    "section",
    "article",
    "h1",
    "h2",
    "h3",
    "h4",
    "tr",
    "pre",
    "blockquote",
}


class _TextExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.blocked: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.rsplit(":", 1)[-1]
        if self.blocked:
            if tag in _BLOCKED_TAGS and tag not in {"embed"}:
                self.blocked.append(tag)
            return
        if tag in _BLOCKED_TAGS:
            if tag != "embed":
                self.blocked.append(tag)
            return
        if tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.rsplit(":", 1)[-1]
        if not self.blocked and tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        tag = tag.rsplit(":", 1)[-1]
        if self.blocked:
            if tag == self.blocked[-1]:
                self.blocked.pop()
            return
        if tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_data(self, data: str) -> None:
        if not self.blocked:
            self.parts.append(data)


def sanitize_text(value: object, *, max_length: int = 20_000) -> str:
    """Extract bounded plain text and discard scripts, boilerplate and controls."""
    if not isinstance(value, str) or max_length <= 0:
        return ""
    # Unescape before parsing so entity-encoded markup receives the same cleaning.
    raw = unescape(value[:131_072])
    parser = _TextExtractor()
    try:
        parser.feed(raw)
        parser.close()
    except (ValueError, AssertionError):
        return ""
    text = _CONTROL.sub("", unicodedata.normalize("NFKC", "".join(parser.parts)))
    lines = [" ".join(line.split()) for line in text.splitlines()]
    return "\n".join(line for line in lines if line and not _NOISE.fullmatch(line))[
        :max_length
    ].strip()


def normalize_content(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).casefold().split())


def find_cves(*values: object) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                match.upper()
                for value in values
                if isinstance(value, str)
                for match in _CVE.findall(value)
            }
        )
    )


def sanitize_url(value: object, *, allow_tracking: bool = False) -> str | None:
    """Return a credential-free HTTPS URL, or None.

    This is syntax checking, not a DNS check. The HTTP transport separately checks
    and pins public resolved addresses before a connection. Evidence links are
    never fetched by this function.
    """
    if not isinstance(value, str) or not value or len(value) > 4096:
        return None
    if any(ord(char) < 33 or ord(char) == 127 for char in value) or "\\" in value:
        return None
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme.lower() != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
        ):
            return None
        host = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
        if (
            host == "localhost"
            or host.endswith((".localhost", ".local", ".internal"))
            or "%" in host
        ):
            return None
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", host) or "." not in host:
                return None
            if any(
                not label or len(label) > 63 or label.startswith("-") or label.endswith("-")
                for label in host.split(".")
            ):
                return None
        else:
            if not address.is_global or (
                isinstance(address, ipaddress.IPv6Address)
                and address.ipv4_mapped
                and not address.ipv4_mapped.is_global
            ):
                return None
        port = parsed.port
        if port is not None and not 1 <= port <= 65535:
            return None
        query = parse_qsl(parsed.query, keep_blank_values=True, max_num_fields=100)
        if any(key.casefold() in _CREDENTIALS for key, _ in query):
            return None
        if not allow_tracking:
            query = [
                (key, val)
                for key, val in query
                if not key.casefold().startswith("utm_") and key.casefold() not in _TRACKERS
            ]
        authority = f"[{host}]" if ":" in host else host
        if port is not None and port != 443:
            authority += f":{port}"
        path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
        return urlunsplit(("https", authority, path, urlencode(query, doseq=True), ""))
    except (ValueError, UnicodeError):
        return None
