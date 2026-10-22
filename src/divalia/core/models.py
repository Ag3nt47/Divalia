"""Small, serializable threat-intelligence data contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import math
import re
from typing import Any, Mapping


_CVE = re.compile(r"CVE-[0-9]{4}-[0-9]{4,19}\Z")


@dataclass(frozen=True, slots=True)
class ThreatBriefing:
    """A source claim, rather than proof of a vulnerability or safe remediation.

    ``credibility`` is the operator-configured source weight. References have not
    been fetched or authenticated. ``cross_reported`` means matching reporting
    arrived from multiple configured hosts; it never means independently verified.
    """

    id: str
    title: str
    summary: str
    source_url: str
    source_kind: str
    cves: tuple[str, ...] = ()
    published_at: str | None = None
    credibility: float = 0.5
    evidence_urls: tuple[str, ...] = ()
    corroboration: str = "unverified"

    def __post_init__(self) -> None:
        for name in ("id", "title", "summary", "source_url", "source_kind"):
            if not isinstance(getattr(self, name), str):
                raise ValueError(f"{name} must be a string")
        if not self.id or not self.title or not self.source_url:
            raise ValueError("id, title and source_url must be nonempty")
        if isinstance(self.credibility, bool) or not isinstance(self.credibility, (int, float)):
            raise ValueError("credibility must be a finite number in [0, 1]")
        if not 0 <= self.credibility <= 1 or not math.isfinite(self.credibility):
            raise ValueError("credibility must be a finite number in [0, 1]")
        if self.published_at is not None and not isinstance(self.published_at, str):
            raise ValueError("published_at must be a string or null")
        if not isinstance(self.cves, tuple) or any(
            not isinstance(cve, str) or not _CVE.fullmatch(cve) for cve in self.cves
        ):
            raise ValueError("cves must be a tuple of canonical CVE identifiers")
        if not isinstance(self.evidence_urls, tuple) or any(
            not isinstance(url, str) for url in self.evidence_urls
        ):
            raise ValueError("evidence_urls must be a tuple of strings")
        if not isinstance(self.corroboration, str) or self.corroboration not in {
            "unverified",
            "cross_reported",
        }:
            raise ValueError("unsupported corroboration status")

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["cves"] = list(self.cves)
        result["evidence_urls"] = list(self.evidence_urls)
        return result

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> ThreatBriefing:
        """Read the JSON representation without silently coercing bad field types."""
        cves = value.get("cves", ())
        evidence_urls = value.get("evidence_urls", ())
        if not isinstance(cves, (list, tuple)) or not isinstance(evidence_urls, (list, tuple)):
            raise ValueError("cves and evidence_urls must be arrays")
        return cls(
            id=value["id"],
            title=value["title"],
            summary=value["summary"],
            source_url=value["source_url"],
            source_kind=value["source_kind"],
            cves=tuple(cves),
            published_at=value.get("published_at"),
            credibility=value.get("credibility", 0.5),
            evidence_urls=tuple(evidence_urls),
            corroboration=value.get("corroboration", "unverified"),
        )
