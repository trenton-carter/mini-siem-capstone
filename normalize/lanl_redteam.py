from __future__ import annotations
from typing import Optional
from datetime import datetime, timezone

from schema import NormalizedEvent, new_event_id


def normalize_lanl_redteam_line(line: str) -> Optional[NormalizedEvent]:
    parts = line.strip().split(",")

    if len(parts) != 4:
        return None

    ts, user, src_computer, dst_computer = parts

    user_clean = user.split("@")[0]

    return NormalizedEvent(
        event_id=new_event_id(),
        timestamp=datetime.now(timezone.utc).isoformat(),
        source="lanl_redteam",
        event_type="lanl_redteam_activity",
        outcome="confirmed_attack",
        user=user_clean,
        host=src_computer,
        message=line.strip(),
        raw_log=line.strip(),
        tags=["lanl", "redteam", "ground_truth"],
        extra={
            "lanl_time": ts,
            "user": user,
            "src_computer": src_computer,
            "dst_computer": dst_computer
        }
    )