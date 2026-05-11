from __future__ import annotations
import json
from collections import Counter

from ingest.readers import read_lines
from normalize.lanl_redteam import normalize_lanl_redteam_line
from storage.db import init_db, insert_events_batch


def write_jsonl(path: str, events):
    with open(path, "w", encoding="utf-8") as f:
        for ev in events:
            f.write(json.dumps(ev.to_dict(), ensure_ascii=False) + "\n")


def main():
    init_db()

    redteam_path = "data/raw/redteam.txt"
    out_path = "data/normalized/lanl_redteam_events.jsonl"

    events = []
    counts = Counter()
    parse_failures = 0

    for line, meta in read_lines(redteam_path, source="lanl_redteam", encoding="utf-8"):
        ev = normalize_lanl_redteam_line(line)

        if ev is None:
            parse_failures += 1
            continue

        events.append(ev)
        counts[ev.event_type] += 1

    insert_events_batch(events)
    write_jsonl(out_path, events)

    print("=== LANL Red Team Integration Test ===")
    print(f"Input file: {redteam_path}")
    print(f"Normalized events written to: {out_path}")
    print(f"Total events normalized: {len(events)}")
    print(f"Parse failures: {parse_failures}")

    print("\nTop event types:")
    for event_type, count in counts.most_common(10):
        print(f"  {event_type}: {count}")


if __name__ == "__main__":
    main()