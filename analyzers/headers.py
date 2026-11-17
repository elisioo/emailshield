"""Compare sender metadata; supplied auth headers are not independent proof."""
import re
from email.utils import parseaddr


def _address(value: str) -> tuple[str, str, str]:
    display, address = parseaddr(value or "")
    domain = address.rsplit("@", 1)[-1].rstrip(".").lower() if "@" in address else ""
    return display, address, domain


def _finding(identifier, level, title, detail, weight, evidence, recommendation):
    return {"id": identifier, "category": "Sender and headers", "level": level,
            "title": title, "detail": detail, "weight": weight,
            "evidence": evidence, "recommendation": recommendation}


def inspect_headers(headers: dict) -> tuple[list[dict], list[dict]]:
    findings = []
    display, from_addr, from_domain = _address(headers.get("from", ""))
    _, reply_addr, reply_domain = _address(headers.get("reply-to", ""))
    _, return_addr, return_domain = _address(headers.get("return-path", ""))
    if from_domain and reply_domain and from_domain != reply_domain:
        findings.append(_finding("SENDER_REPLY_DOMAIN", "medium", "From and Reply-To domains differ",
            "Replies would go to a different domain than the sender. This can be legitimate, but warrants checking.",
            23, f"From: {from_domain} | Reply-To: {reply_domain}",
            "Contact the organization through a known address instead of replying to this message."))
    if from_domain and return_domain and from_domain != return_domain:
        findings.append(_finding("RETURN_PATH_DOMAIN", "low", "Return-Path domain differs",
            "The bounce address differs from the visible sender domain; marketing and forwarding services can do this legitimately.",
            10, f"From: {from_domain} | Return-Path: {return_domain}",
            "Review the sender details and verify unusual requests independently."))
    embedded_address = re.search(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}", display)
    if embedded_address and from_addr.lower() != embedded_address.group(0).lower():
        findings.append(_finding("DISPLAY_NAME_EMAIL", "high", "Display name contains a different email address",
            "An email address shown in the display name does not match the actual From address.", 27,
            f"Display name: {display[:100]} | Actual sender: {from_addr[:100]}",
            "Inspect the real sender address rather than trusting the display name."))

    auth_claims = []
    raw_auth = headers.get("authentication-results", "")
    for method, outcome in re.findall(r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)", raw_auth, flags=re.I):
        item = {"method": method.upper(), "reported_result": outcome.lower(), "verified": False}
        if item not in auth_claims:
            auth_claims.append(item)
    failing = [x for x in auth_claims if x["reported_result"] in {"fail", "softfail", "permerror"}]
    if failing:
        label = ", ".join(f"{x['method']}={x['reported_result']}" for x in failing)
        findings.append(_finding("REPORTED_AUTH_FAILURE", "medium", "Submitted header reports authentication failure",
            "Authentication-Results text claims a failure, but the header itself is untrusted and is not independently validated.",
            15, label + " (unverified header claim)",
            "Do not treat copied authentication headers as verified; confirm suspicious messages separately."))
    return findings, auth_claims
