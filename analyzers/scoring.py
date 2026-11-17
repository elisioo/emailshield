"""Deterministic capped heuristic score with auditable rule weights."""


def score_findings(findings: list[dict]) -> tuple[int, str, list[dict]]:
    severity = {"high": 0, "medium": 1, "low": 2}
    ordered = sorted(findings, key=lambda finding: (severity.get(finding["level"], 3), -finding["weight"], finding["id"]))
    score = min(100, sum(f["weight"] for f in ordered))
    return score, "high" if score >= 60 else "medium" if score >= 25 else "low", ordered
