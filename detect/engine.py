from __future__ import annotations
from detect.rules import (
    rule_ssh_invalid_user_burst,
    rule_ssh_disconnect_burst,
    rule_suspicious_honeypot_activity,
    rule_high_volume_honeypot_source,
)

def run_detection(events):
    alerts = []

    alerts.extend(rule_ssh_invalid_user_burst(events))
    alerts.extend(rule_ssh_disconnect_burst(events))
    alerts.extend(rule_suspicious_honeypot_activity(events))
    alerts.extend(rule_high_volume_honeypot_source(events))

    return alerts