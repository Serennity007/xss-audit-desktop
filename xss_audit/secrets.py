"""Best-effort credential masking. Not a complete secrets detector."""
import re

TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{25,}|github_pat_[A-Za-z0-9_]{30,}|sk-[A-Za-z0-9_-]{20,}|AKIA[A-Z0-9]{16})\b")
ASSIGNED = re.compile(r"(?i)([\"']?\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|secret[_-]?key|password)\b[\"']?\s*[:=]\s*)([\"'])([^\r\n\"']{8,})([\"'])")
PLACEHOLDERS = re.compile(r"(?i)^(?:your[-_ ]|example|placeholder|changeme|<|\$|\[REDACTED|test[-_ ]|dummy[-_ ])")


def secret_locations(text):
    spans = [(m.start(), m.end()) for m in TOKEN.finditer(text)]
    spans.extend((m.start(3), m.end(3)) for m in ASSIGNED.finditer(text)
                 if not PLACEHOLDERS.search(m.group(3)))
    merged = []
    for start, end in sorted(set(spans)):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    return merged


def redact(text: str) -> str:
    for start, end in reversed(secret_locations(text)):
        text = text[:start] + "[REDACTED]" + text[end:]
    return text
