"""Safely parse RFC822/MIME data without following URLs or opening attachments."""
from __future__ import annotations

from email import policy
from email.parser import BytesParser
from pathlib import PurePosixPath, PureWindowsPath
import re

MAX_PARTS = 100
MAX_DEPTH = 16
MAX_TEXT_LENGTH = 240_000


def _clean(value: object, limit: int = 300) -> str:
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", str(value or "")).strip()[:limit]


def _read_text(part) -> str:
    try:
        payload = part.get_payload(decode=True)
        if payload is None:
            text = part.get_payload()
            return text if isinstance(text, str) else ""
        charset = part.get_content_charset() or "utf-8"
        try:
            return payload.decode(charset, errors="replace")
        except (LookupError, ValueError):
            return payload.decode("utf-8", errors="replace")
    except (ValueError, TypeError, LookupError):
        return ""


def parse_email(raw: bytes) -> dict:
    try:
        message = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:
        raise ValueError("The email could not be parsed as message data.") from exc

    headers = {}
    for name in ("from", "to", "reply-to", "return-path", "subject", "authentication-results", "message-id", "date"):
        value = message.get(name)
        if value is not None:
            headers[name] = _clean(value, 1000 if name == "authentication-results" else 300)
    subject = headers.get("subject", "(not provided)")

    plain, html, attachments = [], [], []
    part_stack = [(message, 0)]
    count = 0
    budget = MAX_TEXT_LENGTH
    while part_stack:
        part, depth = part_stack.pop()
        count += 1
        if count > MAX_PARTS or depth > MAX_DEPTH:
            raise ValueError("This email has too many MIME parts or nesting levels.")
        if part.is_multipart():
            try:
                children = list(part.iter_parts())
            except (ValueError, TypeError):
                children = []
            part_stack.extend((child, depth + 1) for child in reversed(children))
            continue
        filename = part.get_filename()
        content_type = _clean(part.get_content_type(), 100)
        disposition = part.get_content_disposition()
        if filename is not None or disposition == "attachment":
            name = _clean(filename or "(unnamed attachment)", 150)
            # Normalize both Unix and Windows path separators; no disk writes.
            name = PurePosixPath(PureWindowsPath(name).name).name
            try:
                data = part.get_payload(decode=True)
                size = len(data) if data is not None else 0
            except (ValueError, TypeError):
                size = 0
            attachments.append({
                "filename": name,
                "extension": ("." + name.rsplit(".", 1)[-1].lower()) if "." in name else "",
                "content_type": content_type,
                "size_bytes": size,
                "disposition": disposition or "unspecified",
            })
            continue
        if content_type not in ("text/plain", "text/html") or budget <= 0:
            continue
        content = _read_text(part)[:budget]
        budget -= len(content)
        (html if content_type == "text/html" else plain).append(content)

    decoded_raw = raw.decode("utf-8", errors="replace")
    # BytesParser interprets content without RFC822 headers as a plain-text body.
    if not any(text.strip() for text in (plain + html)) and not headers and not attachments:
        plain = [decoded_raw[:MAX_TEXT_LENGTH]]
    body = "\n".join(plain + html)
    header_only = bool(headers) and not body.strip()
    return {
        "headers": headers,
        "subject": subject,
        "plain_text": "\n".join(plain),
        "html_text": "\n".join(html),
        "body_text": body,
        "attachments": attachments[:MAX_PARTS],
        "header_only": header_only,
    }
