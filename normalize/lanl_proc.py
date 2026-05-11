from __future__ import annotations
from typing import Optional
from datetime import datetime, timezone

from schema import NormalizedEvent, new_event_id


def normalize_lanl_proc_line(line: str) -> Optional[NormalizedEvent]:
    parts = line.strip().split(",")

    if len(parts) != 5:
        return None

    ts, user, computer, process_name, action = parts

    user_clean = user.split("@")[0]

    event_type = "lanl_process_start" if action.lower() == "start" else "lanl_process_stop"

    return NormalizedEvent(
        event_id=new_event_id(),
        timestamp=datetime.now(timezone.utc).isoformat(),
        source="lanl_proc",
        event_type=event_type,
        outcome="success",
        user=user_clean,
        host=computer,
        message=line.strip(),
        raw_log=line.strip(),
        tags=["lanl", "process"],
        extra={
            "lanl_time": ts,
            "user": user,
            "computer": computer,
            "process_name": process_name,
            "action": action
        }
    )