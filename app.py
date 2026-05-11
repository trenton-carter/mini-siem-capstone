from flask import Flask, render_template, request
import sqlite3
import json

app = Flask(__name__)

DB_PATH = "data/mini_siem.db"


def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def dashboard():
    severity_filter = request.args.get("severity", "")
    rule_filter = request.args.get("rule", "")
    system_filter = request.args.get("system", "")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM events")
    total_events = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*)
        FROM alerts
        WHERE source = 'lanl_detection'
    """)
    total_alerts = cursor.fetchone()[0]

    cursor.execute("""
        SELECT severity, COUNT(*) as count
        FROM alerts
        WHERE source = 'lanl_detection'
        GROUP BY severity
        ORDER BY count DESC
    """)
    severity_rows = cursor.fetchall()
    severity_counts = {row["severity"]: row["count"] for row in severity_rows}

    cursor.execute("""
        SELECT rule_name, COUNT(*) as count
        FROM alerts
        WHERE source = 'lanl_detection'
        GROUP BY rule_name
        ORDER BY count DESC
    """)
    rule_rows = cursor.fetchall()
    rule_counts = {row["rule_name"]: row["count"] for row in rule_rows}

    cursor.execute("""
        SELECT metadata
        FROM alerts
        WHERE source = 'lanl_detection'
    """)

    validated = 0
    for row in cursor.fetchall():
        try:
            metadata = json.loads(row["metadata"])
            if metadata.get("metadata", {}).get("redteam_validated") is True:
                validated += 1
        except Exception:
            pass

    validation_rate = round((validated / total_alerts) * 100, 2) if total_alerts else 0

    query = """
        SELECT rule_name, severity, timestamp, src_ip, description
        FROM alerts
        WHERE source = 'lanl_detection'
    """

    params = []

    if severity_filter:
        query += " AND severity = ?"
        params.append(severity_filter)

    if rule_filter:
        query += " AND rule_name = ?"
        params.append(rule_filter)

    if system_filter:
        query += " AND src_ip LIKE ?"
        params.append(f"%{system_filter}%")

    query += " ORDER BY timestamp DESC LIMIT 50"

    cursor.execute(query, params)
    recent_alerts = cursor.fetchall()

    conn.close()

    return render_template(
        "dashboard.html",
        total_events=total_events,
        total_alerts=total_alerts,
        validated=validated,
        validation_rate=validation_rate,
        critical_alerts=severity_counts.get("critical", 0),
        severity_counts=severity_counts,
        rule_counts=rule_counts,
        recent_alerts=recent_alerts,
        severity_filter=severity_filter,
        rule_filter=rule_filter,
        system_filter=system_filter
    )


if __name__ == "__main__":
    app.run(debug=True)