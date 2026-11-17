"""Educational heuristic rules for common phishing/BEC requests."""
import re

RULES = [
    ("PAYMENT_CHANGE", "medium", "Unusual payment or bank-details language", 24,
     (r"\b(?:wire\s+transfer|bank\s+details|change\s+(?:the|our)\s+bank|new\s+(?:bank\s+account|payment\s+details)|updated\s+bank\s+account|gift\s+cards?)\b"),
     "Payment changes and fund-transfer requests can signal business email compromise.",
     "Verify payment and banking changes using an existing trusted phone number."),
    ("CREDENTIAL_REQUEST", "medium", "Account verification or credential request", 18,
     (r"\b(?:verify\s+your\s+account|confirm\s+your\s+password|reset\s+your\s+password|provide\s+(?:your\s+)?(?:password|login|otp|verification\s+code)|account\s+will\s+be\s+(?:suspended|locked))\b"),
     "A message asks for account verification or secret information.",
     "Use the organization's known website or app instead of email links to manage accounts."),
    ("URGENCY", "low", "Urgency or pressure language", 8,
     (r"\b(?:urgent(?:ly)?|immediate(?:ly)?|act\s+now|within\s+24\s+hours|final\s+warning|right\s+away)\b"),
     "Pressure can be a phishing tactic, but urgent wording alone is not proof of fraud.",
     "Pause before acting on a request that pressures you to respond quickly."),
]


def inspect_language(subject: str, body: str) -> list[dict]:
    content = (subject + "\n" + body)[:240_000]
    results = []
    for identifier, level, title, weight, pattern, detail, recommendation in RULES:
        match = re.search(pattern, content, re.I)
        if match:
            results.append({"id": identifier, "category": "Phishing and BEC", "level": level,
                "title": title, "detail": detail, "weight": weight, "evidence": match.group(0)[:100],
                "recommendation": recommendation})
    return results
