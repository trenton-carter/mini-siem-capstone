import sqlite3
import uuid
import json
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter

from storage.db import clear_lanl_alerts, insert_lanl_alerts_batch

DB_PATH = "data/mini_siem.db"
ALERTS_OUT = "data/alerts/lanl_alerts.jsonl"

TIME_WINDOW = 500
LIMIT_PER_RULE = 5000


def make_alert(rule_name, severity, description, src_computer=None, dst_computer=None, user=None, metadata=None):
    return {
        "alert_id": str(uuid.uuid4()),
        "rule_name": rule_name,
        "severity": severity,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "src_computer": src_computer,
        "dst_computer": dst_computer,
        "user": user,
        "description": description,
        "metadata": metadata or {}
    }


def write_alerts_jsonl(alerts, path=ALERTS_OUT):
    Path("data/alerts").mkdir(parents=True, exist_ok=True)

    with open(path, "w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")


def severity_from_validation(is_redteam_validated, chain_depth):
    if is_redteam_validated and chain_depth >= 3:
        return "critical"
    if is_redteam_validated:
        return "high"
    if chain_depth >= 3:
        return "medium"
    return "low"


def main():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    print("=== LANL Improved Detection Engine v2 ===")
    print(f"Time window threshold: {TIME_WINDOW}")
    print(f"Limit per rule: {LIMIT_PER_RULE}")

    alerts = []

    cursor.execute("""
    SELECT DISTINCT json_extract(extra, '$.dst_computer')
    FROM events
    WHERE source = 'lanl_redteam';
    """)

    redteam_targets = set(row[0] for row in cursor.fetchall() if row[0])

    # Rule 1: Auth -> Process within time window
    cursor.execute(f"""
    SELECT 
        json_extract(a.extra, '$.dst_computer') AS auth_dst,
        a.user AS auth_user,
        CAST(json_extract(a.extra, '$.lanl_time') AS INTEGER) AS auth_time,
        json_extract(p.extra, '$.process_name') AS process_name,
        CAST(json_extract(p.extra, '$.lanl_time') AS INTEGER) AS proc_time,
        p.event_type
    FROM events a
    JOIN events p
    ON json_extract(a.extra, '$.dst_computer') = json_extract(p.extra, '$.computer')
    WHERE a.source = 'lanl_auth'
    AND p.source = 'lanl_proc'
    AND ABS(
        CAST(json_extract(p.extra, '$.lanl_time') AS INTEGER) -
        CAST(json_extract(a.extra, '$.lanl_time') AS INTEGER)
    ) <= {TIME_WINDOW}
    LIMIT {LIMIT_PER_RULE};
    """)

    for row in cursor.fetchall():
        auth_dst, auth_user, auth_time, process_name, proc_time, proc_event = row
        validated = auth_dst in redteam_targets
        severity = severity_from_validation(validated, chain_depth=2)

        alerts.append(make_alert(
            rule_name="timebound_auth_process_chain",
            severity=severity,
            description=f"Authentication activity on {auth_dst} correlated with process activity {process_name} within {TIME_WINDOW} time units.",
            dst_computer=auth_dst,
            user=auth_user,
            metadata={
                "auth_time": auth_time,
                "proc_time": proc_time,
                "time_delta": abs(proc_time - auth_time),
                "process_name": process_name,
                "proc_event": proc_event,
                "redteam_validated": validated,
                "chain_depth": 2
            }
        ))

    # Rule 2: Process -> Network within time window
    cursor.execute(f"""
    SELECT 
        json_extract(p.extra, '$.computer') AS proc_computer,
        json_extract(p.extra, '$.process_name') AS process_name,
        CAST(json_extract(p.extra, '$.lanl_time') AS INTEGER) AS proc_time,
        json_extract(f.extra, '$.dst_computer') AS flow_dst,
        json_extract(f.extra, '$.dst_port') AS flow_dst_port,
        CAST(json_extract(f.extra, '$.lanl_time') AS INTEGER) AS flow_time
    FROM events p
    JOIN events f
    ON json_extract(p.extra, '$.computer') = json_extract(f.extra, '$.src_computer')
    WHERE p.source = 'lanl_proc'
    AND f.source = 'lanl_flows'
    AND ABS(
        CAST(json_extract(f.extra, '$.lanl_time') AS INTEGER) -
        CAST(json_extract(p.extra, '$.lanl_time') AS INTEGER)
    ) <= {TIME_WINDOW}
    LIMIT {LIMIT_PER_RULE};
    """)

    for row in cursor.fetchall():
        proc_computer, process_name, proc_time, flow_dst, flow_dst_port, flow_time = row
        validated = proc_computer in redteam_targets
        severity = severity_from_validation(validated, chain_depth=2)

        alerts.append(make_alert(
            rule_name="timebound_process_network_chain",
            severity=severity,
            description=f"Process {process_name} on {proc_computer} correlated with network activity to {flow_dst} within {TIME_WINDOW} time units.",
            src_computer=proc_computer,
            dst_computer=flow_dst,
            metadata={
                "proc_time": proc_time,
                "flow_time": flow_time,
                "time_delta": abs(flow_time - proc_time),
                "process_name": process_name,
                "dst_port": flow_dst_port,
                "redteam_validated": validated,
                "chain_depth": 2
            }
        ))

    # Rule 3: Auth -> Process -> Network chain
    cursor.execute(f"""
    SELECT
        json_extract(a.extra, '$.dst_computer') AS auth_dst,
        a.user AS auth_user,
        CAST(json_extract(a.extra, '$.lanl_time') AS INTEGER) AS auth_time,
        json_extract(p.extra, '$.process_name') AS process_name,
        CAST(json_extract(p.extra, '$.lanl_time') AS INTEGER) AS proc_time,
        json_extract(f.extra, '$.dst_computer') AS flow_dst,
        json_extract(f.extra, '$.dst_port') AS flow_dst_port,
        CAST(json_extract(f.extra, '$.lanl_time') AS INTEGER) AS flow_time
    FROM events a
    JOIN events p
    ON json_extract(a.extra, '$.dst_computer') = json_extract(p.extra, '$.computer')
    JOIN events f
    ON json_extract(p.extra, '$.computer') = json_extract(f.extra, '$.src_computer')
    WHERE a.source = 'lanl_auth'
    AND p.source = 'lanl_proc'
    AND f.source = 'lanl_flows'
    AND ABS(
        CAST(json_extract(p.extra, '$.lanl_time') AS INTEGER) -
        CAST(json_extract(a.extra, '$.lanl_time') AS INTEGER)
    ) <= {TIME_WINDOW}
    AND ABS(
        CAST(json_extract(f.extra, '$.lanl_time') AS INTEGER) -
        CAST(json_extract(p.extra, '$.lanl_time') AS INTEGER)
    ) <= {TIME_WINDOW}
    LIMIT {LIMIT_PER_RULE};
    """)

    for row in cursor.fetchall():
        auth_dst, auth_user, auth_time, process_name, proc_time, flow_dst, flow_dst_port, flow_time = row
        validated = auth_dst in redteam_targets
        severity = severity_from_validation(validated, chain_depth=3)

        alerts.append(make_alert(
            rule_name="auth_process_network_chain",
            severity=severity,
            description=f"Authentication on {auth_dst} followed by process {process_name} and network activity to {flow_dst}.",
            src_computer=auth_dst,
            dst_computer=flow_dst,
            user=auth_user,
            metadata={
                "auth_time": auth_time,
                "proc_time": proc_time,
                "flow_time": flow_time,
                "auth_to_proc_delta": abs(proc_time - auth_time),
                "proc_to_flow_delta": abs(flow_time - proc_time),
                "process_name": process_name,
                "dst_port": flow_dst_port,
                "redteam_validated": validated,
                "chain_depth": 3
            }
        ))

    # Rule 4: Redteam target with DNS activity
    cursor.execute(f"""
    SELECT
        json_extract(r.extra, '$.dst_computer') AS redteam_dst,
        json_extract(r.extra, '$.user') AS redteam_user,
        json_extract(d.extra, '$.src_computer') AS dns_src,
        json_extract(d.extra, '$.resolved_computer') AS resolved_computer,
        CAST(json_extract(d.extra, '$.lanl_time') AS INTEGER) AS dns_time
    FROM events r
    JOIN events d
    ON json_extract(r.extra, '$.dst_computer') = json_extract(d.extra, '$.src_computer')
    OR json_extract(r.extra, '$.dst_computer') = json_extract(d.extra, '$.resolved_computer')
    WHERE r.source = 'lanl_redteam'
    AND d.source = 'lanl_dns'
    LIMIT {LIMIT_PER_RULE};
    """)

    for row in cursor.fetchall():
        redteam_dst, redteam_user, dns_src, resolved_computer, dns_time = row

        alerts.append(make_alert(
            rule_name="redteam_dns_overlap",
            severity="high",
            description=f"Redteam target {redteam_dst} correlated with DNS activity involving {resolved_computer}.",
            src_computer=dns_src,
            dst_computer=redteam_dst,
            user=redteam_user,
            metadata={
                "dns_time": dns_time,
                "resolved_computer": resolved_computer,
                "redteam_validated": True,
                "chain_depth": 1
            }
        ))

    counts_by_rule = Counter(alert["rule_name"] for alert in alerts)
    counts_by_severity = Counter(alert["severity"] for alert in alerts)
    validated_count = sum(1 for alert in alerts if alert["metadata"].get("redteam_validated") is True)
    detection_rate = (validated_count / len(alerts)) * 100 if alerts else 0

    print(f"\nTotal structured alerts generated: {len(alerts)}")
    print(f"Redteam-validated alerts: {validated_count}")
    print(f"Validation rate: {detection_rate:.2f}%")

    print("\nAlerts by rule:")
    for rule, count in counts_by_rule.items():
        print(f"  {rule}: {count}")

    print("\nAlerts by severity:")
    for severity, count in counts_by_severity.items():
        print(f"  {severity}: {count}")

    print("\nSample alerts:")
    for alert in alerts[:5]:
        print(alert)

    clear_lanl_alerts()
    insert_lanl_alerts_batch(alerts)
    write_alerts_jsonl(alerts)

    print("\nAlert storage complete.")
    print("Alerts written to: data/alerts/lanl_alerts.jsonl")
    print("Alerts inserted into SQLite alerts table.")

    conn.close()


if __name__ == "__main__":
    main()