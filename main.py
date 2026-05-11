from __future__ import annotations
from storage.db import init_db
from storage.db import insert_events_batch
import json
from collections import Counter

from ingest.readers import read_lines
from normalize.authlog_parser import normalize_authlog_line
from normalize.honeypot import normalize_honeypot_line

def write_jsonl(path: str, events):
    with open(path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")

def main():
    init_db()
    # filename paths
    auth_path = "data/raw/auth.log"
    honeypot_path = "data/raw/honeypot.json"
    out_path = "data/normalized/events.jsonl"

    # IMPORTANT: the auth.log has no year. Pick the correct year manually.
    # If unknown, use the year the dataset was collected or just use current year.
    auth_year = 2026

    events = []
    counts = Counter()
    parse_failures = 0

    # Auth log
    for line, meta in read_lines(auth_path, source="authlog"):
        ev = normalize_authlog_line(line, year=auth_year)
        events.append(ev)
        counts[ev.event_type] += 1
        if ev.event_type.startswith("unparsed"):
            parse_failures += 1

    # Honeypot JSON
    for line, meta in read_lines(honeypot_path, source="honeypot"):
        try:
            ev = normalize_honeypot_line(line)
            events.append(ev)
            counts[ev.event_type] += 1
        except Exception:
            parse_failures += 1

    insert_events_batch(events)

    write_jsonl(out_path, events)

    print("=== Mini SIEM Week 4: Ingestion + Normalization ===")
    print(f"Normalized events written to: {out_path}")
    print(f"Total events: {len(events)}")
    print(f"Parse failures: {parse_failures}")
    print("\nTop event types:")
    for k, v in counts.most_common(10):
        print(f"  {k}: {v}")

if __name__ == "__main__":
    main()