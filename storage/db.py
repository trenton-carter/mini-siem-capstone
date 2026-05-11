import sqlite3
import json
import json
import uuid
from pathlib import Path
from datetime import datetime, timezone

DB_PATH = Path("data/mini_siem.db")


def get_connection():
    """Create and return a SQLite connection."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    return sqlite3.connect(DB_PATH)


def init_db():
    """Initialize the SQLite database and create required tables."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            event_id TEXT PRIMARY KEY,
            timestamp TEXT,
            source TEXT,
            event_type TEXT,
            outcome TEXT,
            host TEXT,
            user TEXT,
            src_ip TEXT,
            src_port INTEGER,
            dest_ip TEXT,
            dest_port INTEGER,
            program TEXT,
            pid INTEGER,
            message TEXT,
            tags TEXT,
            raw_log TEXT,
            extra TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            alert_id TEXT PRIMARY KEY,
            rule_name TEXT,
            severity TEXT,
            timestamp TEXT,
            source TEXT,
            src_ip TEXT,
            description TEXT,
            related_event_ids TEXT,
            metadata TEXT
        )
    """)

    conn.commit()
    conn.close()


def insert_events_batch(events):
    """Insert a batch of normalized events into the database."""
    conn = get_connection()
    cursor = conn.cursor()

    rows = []
    for event in events:
        rows.append((
            event.event_id,
            event.timestamp,
            event.source,
            event.event_type,
            event.outcome,
            event.host,
            event.user,
            event.src_ip,
            event.src_port,
            event.dest_ip,
            event.dest_port,
            event.program,
            event.pid,
            event.message,
            ",".join(event.tags) if event.tags else None,
            event.raw_log,
            json.dumps(event.extra) if event.extra else None
        ))

    cursor.executemany("""
        INSERT OR IGNORE INTO events (
            event_id, timestamp, source, event_type, outcome,
            host, user, src_ip, src_port,
            dest_ip, dest_port,
            program, pid, message,
            tags, raw_log, extra
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)

    conn.commit()
    conn.close()


def insert_alerts_batch(alerts):
    """Insert a batch of alerts into the database."""
    conn = get_connection()
    cursor = conn.cursor()

    rows = []
    for alert in alerts:
        rows.append((
            alert["alert_id"],
            alert["rule_name"],
            alert["severity"],
            alert["timestamp"],
            alert["source"],
            alert.get("src_ip"),
            alert["description"],
            json.dumps(alert.get("related_event_ids", [])),
            json.dumps(alert.get("metadata", {}))
        ))

    cursor.executemany("""
        INSERT OR IGNORE INTO alerts (
            alert_id, rule_name, severity, timestamp, source,
            src_ip, description, related_event_ids, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)

    conn.commit()
    conn.close()

def clear_lanl_alerts():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        DELETE FROM alerts
        WHERE source = 'lanl_detection'
    """)

    conn.commit()
    conn.close()


def insert_lanl_alerts_batch(alerts):
    conn = get_connection()
    cursor = conn.cursor()

    rows = []
    for alert in alerts:
        rows.append((
            alert["alert_id"],
            alert["rule_name"],
            alert["severity"],
            alert["timestamp"],
            "lanl_detection",
            alert.get("src_computer"),
            alert["description"],
            json.dumps([]),
            json.dumps(alert)
        ))

    cursor.executemany("""
        INSERT OR IGNORE INTO alerts (
            alert_id, rule_name, severity, timestamp, source,
            src_ip, description, related_event_ids, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, rows)

    conn.commit()
    conn.close()