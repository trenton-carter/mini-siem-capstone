from __future__ import annotations
import uuid
from datetime import datetime, timezone

def make_alert(rule_name, severity, source, src_ip, description, related_event_ids=None, metadata=None):
    return {
        "alert_id": str(uuid.uuid4()),
        "rule_name": rule_name,
        "severity": severity,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": source,
        "src_ip": src_ip,
        "description": description,
        "related_event_ids": related_event_ids or [],
        "metadata": metadata or {}
    }

def rule_ssh_invalid_user_burst(events):
    alerts = []
    grouped = {}

    for event in events:
        if event["event_type"] == "ssh_invalid_user" and event.get("src_ip"):
            grouped.setdefault(event["src_ip"], []).append(event)

    for src_ip, matches in grouped.items():
        if len(matches) >= 5:
            alerts.append(make_alert(
                rule_name="ssh_invalid_user_burst",
                severity="high",
                source="authlog",
                src_ip=src_ip,
                description=f"Detected {len(matches)} invalid SSH user attempts from {src_ip}.",
                related_event_ids=[e["event_id"] for e in matches[:20]],
                metadata={"count": len(matches)}
            ))

    return alerts

def rule_ssh_disconnect_burst(events):
    alerts = []
    grouped = {}

    for event in events:
        if event["event_type"] == "ssh_disconnect" and event.get("src_ip"):
            grouped.setdefault(event["src_ip"], []).append(event)

    for src_ip, matches in grouped.items():
        if len(matches) >= 10:
            alerts.append(make_alert(
                rule_name="ssh_disconnect_burst",
                severity="medium",
                source="authlog",
                src_ip=src_ip,
                description=f"Detected {len(matches)} SSH disconnect events from {src_ip}.",
                related_event_ids=[e["event_id"] for e in matches[:20]],
                metadata={"count": len(matches)}
            ))

    return alerts

def rule_suspicious_honeypot_activity(events):
    alerts = []

    for event in events:
        tags = event.get("tags", [])
        if isinstance(tags, str):
            tags = tags.split(",")

        if event["source"] == "honeypot" and ("suspicious" in tags or "command_injection" in tags):
            alerts.append(make_alert(
                rule_name="suspicious_honeypot_activity",
                severity="high",
                source="honeypot",
                src_ip=event.get("src_ip"),
                description="Detected suspicious honeypot activity with command injection indicators.",
                related_event_ids=[event["event_id"]],
                metadata={"event_type": event["event_type"]}
            ))

    return alerts

def rule_high_volume_honeypot_source(events):
    alerts = []
    grouped = {}

    for event in events:
        if event["source"] == "honeypot" and event.get("src_ip"):
            grouped.setdefault(event["src_ip"], []).append(event)

    for src_ip, matches in grouped.items():
        if len(matches) >= 100:
            alerts.append(make_alert(
                rule_name="high_volume_honeypot_source",
                severity="medium",
                source="honeypot",
                src_ip=src_ip,
                description=f"Detected high-volume honeypot activity from {src_ip} with {len(matches)} events.",
                related_event_ids=[e["event_id"] for e in matches[:20]],
                metadata={"count": len(matches)}
            ))

    return alerts