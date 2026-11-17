"""Orchestration for deterministic educational checks. Never contacts outside services."""
from __future__ import annotations

from .parsing import parse_email
from .headers import inspect_headers
from .urls import inspect_urls
from .attachments import inspect_attachments
from .language import inspect_language
from .scoring import score_findings

MAX_EMAIL_BYTES = 2 * 1024 * 1024
MAX_PASTE_CHARS = 200_000


def analyze_email(raw: bytes, source: str = "Pasted email") -> dict:
    if not raw or not raw.strip():
        raise ValueError("Paste an email or choose a nonempty file.")
    if len(raw) > MAX_EMAIL_BYTES:
        raise ValueError("Email is larger than the 2 MB analysis limit.")
    parsed = parse_email(raw)
    sender_findings, auth_claims = inspect_headers(parsed["headers"])
    link_findings, links = inspect_urls(parsed["plain_text"], parsed["html_text"])
    attachment_findings = inspect_attachments(parsed["attachments"])
    language_findings = inspect_language(parsed["subject"], parsed["body_text"])
    findings = sender_findings + link_findings + attachment_findings + language_findings
    score, level, ordered = score_findings(findings)

    return {
        "source": source[:100],
        "subject": parsed["subject"],
        "from": parsed["headers"].get("from", "(not available)"),
        "reply": parsed["headers"].get("reply-to", "(not available)"),
        "return_path": parsed["headers"].get("return-path", "(not available)"),
        "authentication_claims": auth_claims,
        "header_only": parsed["header_only"],
        "links": links,
        "attachments": parsed["attachments"],
        "findings": ordered,
        "score": score,
        "level": level,
        "recommendations": _recommendations(ordered),
        "limitations": [
            "Risk scores reflect heuristic indicators and are not proof of safety or maliciousness.",
            "Authentication-Results claims are copied from the submitted email, not independently verified.",
            "URLs are never visited and no live threat-intelligence service is queried.",
            "Attachment files are not executed, extracted, or malware-scanned.",
            "Email content is processed in memory and not stored by default.",
        ],
        "analysis_version": "1.0",
    }


def _recommendations(findings: list[dict]) -> list[str]:
    base = ["Do not open unexpected attachments or follow links until the sender is verified."]
    for item in findings:
        rec = item.get("recommendation")
        if rec and rec not in base:
            base.append(rec)
    if not findings:
        base.append("No indicator matched these rules; that does not establish the email is safe.")
    return base[:7]
