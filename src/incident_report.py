import re
import textwrap
import unicodedata

from src.alert_schema import utc_iso


_SECRET = re.compile(
    r"(?i)\b(api[_-]?key|authorization|cookie|password|secret|token)\b\s*[:=]\s*[^\s,;]+"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")


def _safe(value, limit=1200):
    text = " ".join(str(value if value is not None else "N/A").split())[:limit]
    text = _BEARER.sub("Bearer [REDACTED]", text)
    return _SECRET.sub(lambda match: f"{match.group(1)}=[REDACTED]", text)


def _utc(value):
    if value in (None, ""):
        return "N/A"
    try:
        return utc_iso(value)
    except (TypeError, ValueError):
        return _safe(value)


def _items(values):
    return [_safe(value) for value in values if value not in (None, "", [])]


def incident_report_sections(alert):
    """Build a deterministic allowlisted report model from one stored incident."""
    incident_id = _safe(alert.get("incident_id"))
    status = _safe(alert.get("incident_status") or "NEW")
    timeline = list(alert.get("timeline") or [])
    notes = list(alert.get("analyst_notes") or [])
    actions = list(alert.get("response_actions") or [])
    ai = alert.get("ai_analysis") or {}
    intel = alert.get("threat_intel") or {}

    evidence = [
        f"Alert name: {_safe(alert.get('alert_name'))}",
        f"Observed at: {_utc(alert.get('timestamp'))}",
        f"Recorded at: {_utc(alert.get('created_at'))}",
        f"Severity: {_safe(alert.get('severity'))}",
        f"Source type: {_safe(alert.get('source_type'))}",
        f"Description: {_safe(alert.get('description'))}",
        f"Source IP: {_safe(alert.get('ip_address'))}",
        f"Event count: {_safe(alert.get('event_count', 1))}",
        f"Rule ID: {_safe(alert.get('rule_id'))}",
        f"Risk: {_safe(alert.get('risk_score', 0))}/100 {_safe(alert.get('risk_level', 'LOW'))}",
    ]
    factors = [
        f"- {_safe(item.get('factor'))}: +{_safe(item.get('points'))} ({_safe(item.get('value'))})"
        for item in alert.get("risk_factors") or [] if isinstance(item, dict)
    ]
    ai_lines = ["AI-generated assessment; not observed fact."]
    if ai:
        ai_lines += [
            f"Provider/model: {_safe(ai.get('provider'))} / {_safe(ai.get('model'))}",
            f"Analysed at: {_utc(ai.get('analysed_at'))}",
            f"Disposition: {_safe(alert.get('ai_disposition'))}",
            f"Recommended severity: {_safe(alert.get('ai_recommended_severity'))}",
            f"Threat confidence: {_safe(ai.get('threat_confidence'))}%",
            f"False-positive confidence: {_safe(ai.get('fp_confidence'))}%",
            f"Human review: {'required' if ai.get('escalate_to_human') else 'not required'}",
            f"Summary: {_safe(ai.get('threat_summary'))}",
        ] + [f"Playbook: {_safe(step)}" for step in ai.get("recommended_playbook") or []]
    else:
        ai_lines.append("No stored AI assessment.")

    intel_lines = ["Third-party context; not detector evidence."]
    for provider in sorted(intel):
        entry = intel[provider]
        if not isinstance(entry, dict):
            continue
        fields = _items([
            entry.get("status"), entry.get("ioc_type"), entry.get("ioc"),
            entry.get("confidence"), entry.get("abuse_confidence"),
            entry.get("total_reports"), entry.get("malicious"),
            entry.get("suspicious"), entry.get("match_count"),
            ", ".join(entry.get("sources") or []), ", ".join(entry.get("labels") or []),
        ])
        intel_lines.append(f"{_safe(provider)}: {' | '.join(fields) if fields else 'no stored result'}")
    if len(intel_lines) == 1:
        intel_lines.append("No stored threat intelligence.")

    timeline_lines = [f"Created: {_utc(alert.get('created_at') or alert.get('timestamp'))}"]
    timeline_lines += [
        f"{_utc(event.get('timestamp'))}: {_safe(event.get('event_type', 'UPDATED'))}"
        + (f" {_safe(event.get('from_status'))} -> {_safe(event.get('to_status'))}" if event.get("to_status") else "")
        for event in timeline if isinstance(event, dict)
    ]
    timeline_lines += [
        f"Note {_utc(note.get('timestamp'))} by {_safe(note.get('author', 'analyst'))}: {_safe(note.get('text'))}"
        for note in notes if isinstance(note, dict)
    ]
    action_lines = [
        f"{_utc(action.get('created_at'))}: {_safe(action.get('action_type'))} "
        f"target={_safe(action.get('target'))} status={_safe(action.get('status'))} "
        f"mode={_safe(action.get('mode'))}"
        for action in actions if isinstance(action, dict)
    ] or ["No stored response actions."]
    resolution_event = next((
        event for event in timeline if isinstance(event, dict)
        and event.get("event_type") == "STATUS_CHANGED"
        and event.get("to_status") in {"RESOLVED", "FALSE_POSITIVE"}
    ), None)

    return [
        ("Incident Metadata", [
            f"Incident ID: {incident_id}", f"Alert ID: {_safe(alert.get('alert_id'))}",
            f"Status: {status}", f"Assignee: {_safe(alert.get('assigned_to') or 'Unassigned')}",
            f"Last updated: {_utc(alert.get('updated_at'))}",
        ]),
        ("Executive Summary", [
            f"{_safe(alert.get('alert_name'))} was recorded as a {_safe(alert.get('severity'))} "
            f"incident from {_safe(alert.get('source_type'))}. Current status: {status}."
        ]),
        ("Detection Evidence", evidence + factors),
        ("MITRE Mapping", [f"Technique: {_safe(alert.get('mitre_attck_id') or 'Not mapped')}"]),
        ("AI Analysis", ai_lines),
        ("Threat Intelligence", intel_lines),
        ("Asset Context", [f"Stored asset reference: {_safe(alert.get('asset_id') or 'Not linked')}"]),
        ("Analyst Timeline", timeline_lines),
        ("Response Actions", action_lines),
        ("Resolution", [
            f"Current status: {status}",
            f"Resolution timestamp: {_utc(resolution_event.get('timestamp')) if resolution_event else 'Not resolved'}",
        ]),
        ("Appendix", [
            "Report schema: Mini-SIEM incident PDF v1",
            "Source: stored incident record; generated without live AI or threat-intelligence calls.",
            "Excluded by design: raw log payloads, provider raw responses, secrets, and response commands.",
        ]),
    ]


def _ascii(text):
    # ponytail: built-in PDF font keeps deployment dependency-free; embed a Unicode font if exact glyph fidelity is required.
    text = str(text).replace("đ", "d").replace("Đ", "D")
    return unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode("ascii")


def _pdf_pages(title, sections):
    lines = [("title", _safe(title))]
    for heading, values in sections:
        lines.append(("heading", heading))
        lines.extend(("body", value) for value in values)
    pages, page, y = [], [], 792
    for style, value in lines:
        size, leading, width = {"title": (18, 25, 58), "heading": (13, 20, 78)}.get(style, (9, 13, 105))
        for wrapped in textwrap.wrap(_ascii(value), width=width, break_long_words=True) or [""]:
            if y - leading < 45:
                pages.append(page)
                page, y = [], 792
            page.append((size, y, wrapped))
            y -= leading
    pages.append(page)
    return pages


def generate_incident_pdf(alert):
    if not alert.get("incident_id"):
        raise ValueError("Alert is not linked to an incident")
    pages = _pdf_pages(f"Mini-SIEM Incident Report - {alert['incident_id']}", incident_report_sections(alert))
    objects = {1: b"<< /Type /Catalog /Pages 2 0 R >>", 3: b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"}
    kids = []
    for index, page in enumerate(pages):
        page_id, content_id = 4 + index * 2, 5 + index * 2
        kids.append(f"{page_id} 0 R")
        commands = []
        for size, y, line in page:
            escaped = line.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            commands.append(f"BT /F1 {size} Tf 50 {y} Td ({escaped}) Tj ET")
        commands.append(f"BT /F1 8 Tf 50 25 Td (Page {index + 1} of {len(pages)}) Tj ET")
        stream = "\n".join(commands).encode("ascii")
        objects[page_id] = (
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 842] "
            f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
        ).encode("ascii")
        objects[content_id] = f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream"
    objects[2] = f"<< /Type /Pages /Kids [{' '.join(kids)}] /Count {len(pages)} >>".encode("ascii")

    output = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for object_id in range(1, max(objects) + 1):
        offsets.append(len(output))
        output.extend(f"{object_id} 0 obj\n".encode("ascii"))
        output.extend(objects[object_id])
        output.extend(b"\nendobj\n")
    xref = len(output)
    output.extend(f"xref\n0 {len(offsets)}\n0000000000 65535 f \n".encode("ascii"))
    output.extend("".join(f"{offset:010d} 00000 n \n" for offset in offsets[1:]).encode("ascii"))
    output.extend(
        f"trailer\n<< /Size {len(offsets)} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii")
    )
    return bytes(output)
