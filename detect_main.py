from __future__ import annotations
import sqlite3
import json
from collections import Counter

from detect.engine import run_detection
from storage.db import insert_alerts_batch

DB_PATH = "data/mini_siem.db"
ALERTS_OUT = "data/alerts/alerts.jsonl"

def load_events():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()

    cursor.execute("""
        SELECT event_id, timestamp, source, event_type, outcome,
               host, user, src_ip, src_port, dest_ip, dest_port,
               program, pid, message, tags, raw_log, extra
        FROM events
    """)

    rows = cursor.fetchall()
    conn.close()

    events = []
    for row in rows:
        event = dict(row)
        if event.get("tags"):
            event["tags"] = event["tags"].split(",")
        else:
            event["tags"] = []

        if event.get("extra"):
            try:
                event["extra"] = json.loads(event["extra"])
            except Exception:
                event["extra"] = {}
        else:
            event["extra"] = {}

        events.append(event)

    return events

def write_alerts_jsonl(path, alerts):
    with open(path, "w", encoding="utf-8") as f:
        for alert in alerts:
            f.write(json.dumps(alert, ensure_ascii=False) + "\n")

def main():
    events = load_events()
    alerts = run_detection(events)

    insert_alerts_batch(alerts)
    write_alerts_jsonl(ALERTS_OUT, alerts)

    counts = Counter(alert["rule_name"] for alert in alerts)

    print("=== Mini SIEM Week 6: Detection Rules ===")
    print(f"Total events loaded: {len(events)}")
    print(f"Total alerts generated: {len(alerts)}")
    print("\nAlerts by rule:")
    for rule, count in counts.items():
        print(f"  {rule}: {count}")

if __name__ == "__main__":
    main()