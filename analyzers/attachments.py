"""Analyze filenames and MIME metadata only; never execute/extract contents."""
from __future__ import annotations
import re

HIGH_EXT = {".exe", ".scr", ".js", ".jse", ".vbs", ".vbe", ".ps1", ".bat", ".cmd", ".hta", ".jar", ".lnk", ".msi", ".com", ".pif"}
MED_EXT = {".docm", ".xlsm", ".pptm", ".iso", ".img", ".zip", ".rar", ".7z"}
DOUBLE_EXT = re.compile(r"\.(?:pdf|docx?|xlsx?|txt|jpg|png)\.(?:exe|scr|js|bat|cmd|vbs|ps1)$", re.I)


def inspect_attachments(attachments: list[dict]) -> list[dict]:
    findings = []
    risky = [a for a in attachments if a["extension"] in HIGH_EXT]
    macro = [a for a in attachments if a["extension"] in MED_EXT]
    double = [a for a in attachments if DOUBLE_EXT.search(a["filename"])]
    if risky:
        findings.append({"id": "DANGEROUS_FILE_EXTENSION", "category": "Attachments", "level": "high",
            "title": "Potentially executable attachment type", "detail": "One or more file extensions are commonly used to run code or scripts.",
            "weight": 34, "evidence": ", ".join(a["filename"] for a in risky[:5]),
            "recommendation": "Do not run unexpected executable or script attachments."})
    if double:
        findings.append({"id": "DOUBLE_EXTENSION", "category": "Attachments", "level": "high",
            "title": "Deceptive double-extension filename", "detail": "A filename appears to disguise an executable/script as a document or image.",
            "weight": 20, "evidence": ", ".join(a["filename"] for a in double[:5]),
            "recommendation": "Check the complete attachment filename and avoid opening disguised files."})
    if macro:
        findings.append({"id": "MACRO_OR_ARCHIVE_EXTENSION", "category": "Attachments", "level": "medium",
            "title": "Macro-enabled or archive attachment", "detail": "The attachment type can contain active content or additional files; content was not inspected.",
            "weight": 15, "evidence": ", ".join(a["filename"] for a in macro[:5]),
            "recommendation": "Verify unexpected archives or macro-enabled files through a trusted channel."})
    return findings
