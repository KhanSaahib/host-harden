"""Data types shared across parsers, checks, and report formatting."""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITIES = ("high", "medium", "low", "info")


@dataclass
class CheckResult:
    """The outcome of one hardening check."""

    id: str
    category: str
    title: str
    status: str  # "pass", "fail", or "unknown"
    detail: str
    severity: str = "info"  # meaningful only when status == "fail"
    remediation: str = ""
    source: str = ""  # which input file this check ran against

    def __post_init__(self) -> None:
        if self.status not in ("pass", "fail", "unknown"):
            raise ValueError(f"invalid status: {self.status!r}")
        if self.status == "fail" and self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity: {self.severity!r}")


@dataclass
class Report:
    """A full run: every check result plus a computed summary."""

    results: list[CheckResult] = field(default_factory=list)

    def extend(self, results: list[CheckResult]) -> None:
        self.results.extend(results)

    @property
    def failed(self) -> list[CheckResult]:
        return [r for r in self.results if r.status == "fail"]

    @property
    def passed(self) -> list[CheckResult]:
        return [r for r in self.results if r.status == "pass"]

    @property
    def unknown(self) -> list[CheckResult]:
        return [r for r in self.results if r.status == "unknown"]

    def counts_by_severity(self) -> dict[str, int]:
        counts = {s: 0 for s in SEVERITIES}
        for r in self.failed:
            counts[r.severity] += 1
        return counts

    def score(self) -> float:
        """Percentage of evaluated (non-unknown) checks that passed."""
        evaluated = len(self.passed) + len(self.failed)
        if evaluated == 0:
            return 0.0
        return round(100.0 * len(self.passed) / evaluated, 1)

    def highest_severity_failed(self) -> str | None:
        for sev in ("high", "medium", "low"):
            if any(r.severity == sev for r in self.failed):
                return sev
        return None
