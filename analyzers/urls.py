"""URL pattern analysis. Never fetches, opens, resolves, or follows any URL."""
from __future__ import annotations
from html.parser import HTMLParser
import ipaddress
import re
from urllib.parse import urlsplit

URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"'\[\]{}]+", re.I)
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rb.gy", "shorturl.at"}
MAX_URLS = 80


class LinkExtractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self.text_parts = []
        self.outside_link_text = []
        self.current_link = None
        self.ignored_depth = 0

    def handle_starttag(self, tag, attrs):
        tag = tag.lower()
        if tag in {"script", "style"}:
            self.ignored_depth += 1
        if tag == "a" and self.current_link is None:
            href = dict(attrs).get("href", "") or ""
            self.current_link = [href, []]

    def handle_data(self, data):
        if self.ignored_depth:
            return
        self.text_parts.append(data)
        if self.current_link:
            self.current_link[1].append(data)
        else:
            self.outside_link_text.append(data)

    def handle_endtag(self, tag):
        tag = tag.lower()
        if tag in {"script", "style"}:
            self.ignored_depth = max(0, self.ignored_depth - 1)
        if tag == "a" and self.current_link:
            self.links.append((self.current_link[0], " ".join(self.current_link[1]).strip()))
            self.current_link = None


def _host(text: str) -> str:
    try:
        candidate = text if not text.lower().startswith("www.") else "https://" + text
        parsed = urlsplit(candidate)
        return (parsed.hostname or "").lower().rstrip(".")
    except ValueError:
        return ""


def _add_flag(flags: dict, identifier: str, level: str, title: str, weight: int,
              detail: str, evidence: str, recommendation: str) -> None:
    if identifier not in flags:
        flags[identifier] = {"id": identifier, "category": "Links", "level": level,
                             "title": title, "detail": detail, "weight": weight,
                             "evidence": evidence[:200], "recommendation": recommendation}


def inspect_urls(plain_text: str, html_text: str) -> tuple[list[dict], list[dict]]:
    parser = LinkExtractor()
    try:
        parser.feed(html_text[:240_000])
        parser.close()
    except (ValueError, TypeError):
        pass

    candidates = [(m.group(0).rstrip(".,;!?):"), "") for m in URL_RE.finditer(plain_text + "\n" + " ".join(parser.outside_link_text))]
    candidates += parser.links
    urls, seen, flags = [], set(), {}
    for value, label in candidates:
        value = value.strip()
        if not value or len(value) > 2048:
            continue
        if re.match(r"^(?:javascript|data|file):", value, re.I):
            _add_flag(flags, "NON_WEB_LINK", "high", "Potentially unsafe link scheme", 27,
                      "An HTML link uses a script, data, or local-file scheme rather than a normal web address.",
                      value.split(":", 1)[0].lower() + ":", "Do not activate unexpected interactive links inside email messages.")
            continue
        if not re.match(r"^(?:https?://|www\.)", value, re.I):
            continue
        host = _host(value)
        if not host:
            continue
        if value not in seen:
            urls.append({"url": value[:500], "host": host, "label": label[:100]})
            seen.add(value)
        if len(urls) >= MAX_URLS:
            break
        parse_value = "https://" + value if value.lower().startswith("www.") else value
        try:
            parsed = urlsplit(parse_value)
        except ValueError:
            continue
        try:
            ipaddress.ip_address(host)
            _add_flag(flags, "URL_IP_ADDRESS", "high", "Link points to a raw IP address", 31,
                      "The URL points directly to an IP address rather than a named domain.",
                      host, "Confirm the destination through a trusted website, not this link.")
        except ValueError:
            pass
        if parsed.scheme == "http":
            _add_flag(flags, "URL_HTTP", "low", "Unencrypted HTTP link", 9,
                      "The link uses HTTP instead of HTTPS. This alone does not prove maliciousness.", host,
                      "Avoid entering credentials or other sensitive details over HTTP.")
        if parsed.username is not None or "@" in parsed.netloc:
            _add_flag(flags, "URL_USERINFO", "high", "Link has deceptive user-information syntax", 28,
                      "An @ sign or credentials in a URL can disguise the actual destination host.", host,
                      "Inspect the actual destination hostname carefully.")
        if host.startswith("xn--") or ".xn--" in host:
            _add_flag(flags, "URL_PUNYCODE", "medium", "Internationalized domain encoding", 15,
                      "The URL uses punycode; look-alike international domains sometimes use this format.", host,
                      "Check the spelling and identity of the destination domain.")
        if host in SHORTENERS:
            _add_flag(flags, "URL_SHORTENER", "medium", "Shortened destination link", 13,
                      "The shortened URL hides the final destination; EmailShield does not resolve it.", host,
                      "Confirm an unfamiliar shortened URL independently before visiting it.")
        # A link's visible text can say one host while its href sends the user elsewhere.
        if label:
            visible_match = URL_RE.search(label.strip())
            if visible_match:
                visible_host = _host(visible_match.group(0).rstrip(".,;!?:)"))
                if visible_host and visible_host.removeprefix("www.") != host.removeprefix("www."):
                    _add_flag(flags, "URL_LABEL_MISMATCH", "high", "Visible link and destination differ", 32,
                              "The domain shown in the link text does not match the clickable destination.",
                              f"Shown: {visible_host} | Destination: {host}",
                              "Do not trust a link based only on its visible label.")
    return list(flags.values()), urls
