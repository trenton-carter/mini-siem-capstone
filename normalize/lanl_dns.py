from __future__ import annotations
from typing import Optional
from datetime import datetime, timezone

from schema import NormalizedEvent, new_event_id


def normalize_lanl_dns_line(line: str) -> Optional[NormalizedEvent]:
    parts = line.strip().split(",")

    if len(parts) != 3:
        return None

    ts, src_computer, resolved_computer = parts

    return NormalizedEvent(
        event_id=new_event_id(),
        timestamp=datetime.now(timezone.utc).isoformat(),
        source="lanl_dns",
        event_type="lanl_dns_lookup",
        outcome="observed",
        host=src_computer,
        message=line.strip(),
        raw_log=line.strip(),
        tags=["lanl", "dns"],
        extra={
            "lanl_time": ts,
            "src_computer": src_computer,
            "resolved_computer": resolved_computer
        }
    )