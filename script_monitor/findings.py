from __future__ import annotations

from dataclasses import asdict, dataclass

SEVERITIES = ("critical", "high", "medium", "low", "info")
WEIGHTS = {"critical": 40, "high": 20, "medium": 8, "low": 2, "info": 0}


@dataclass
class Finding:
    severity: str
    code: str
    title: str
    detail: str = ""
    resource: str | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def score(findings: list[dict]) -> int:
    return min(100, sum(WEIGHTS.get(f["severity"], 0) for f in findings))


def verdict(findings: list[dict]) -> str:
    sevs = {f["severity"] for f in findings}
    if "critical" in sevs:
        return "INVESTIGATE NOW"
    if "high" in sevs:
        return "NEEDS HARDENING"
    if "medium" in sevs:
        return "REVIEW"
    return "LOOKS GOOD"


def sort_findings(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: (SEVERITIES.index(f["severity"]), f["code"]))
