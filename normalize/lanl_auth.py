from __future__ import annotations
from typing import Optional
from datetime import datetime, timezone

from schema import NormalizedEvent, new_event_id


def normalize_lanl_auth_line(line: str) -> Optional[NormalizedEvent]:
    parts = line.strip().split(",")

    if len(parts) != 9:
        return None

    ts, src_user, dst_user, src_computer, dst_computer, auth_type, logon_type, auth_orientation, success = parts

    # Extract usernames (before @)
    src_user_clean = src_user.split("@")[0]
    dst_user_clean = dst_user.split("@")[0]

    # Convert timestamp (LANL uses integer time)
    timestamp = datetime.now(timezone.utc).isoformat()

    # Determine event type
    if auth_orientation == "LogOn":
        event_type = "lanl_logon"
    elif auth_orientation == "LogOff":
        event_type = "lanl_logoff"
    else:
        event_type = "lanl_auth_other"

    outcome = "success" if success.lower() == "success" else "failure"

    return NormalizedEvent(
        event_id=new_event_id(),
        timestamp=timestamp,
        source="lanl_auth",
        event_type=event_type,
        outcome=outcome,
        user=src_user_clean,
        src_ip=None,
        host=src_computer,
        message=line.strip(),
        raw_log=line.strip(),
        tags=["lanl", "auth"],
        extra={
            "lanl_time": ts,
            "src_user": src_user,
            "dst_user": dst_user,
            "src_computer": src_computer,
            "dst_computer": dst_computer,
            "auth_type": auth_type,
            "logon_type": logon_type,
            "auth_orientation": auth_orientation,
            "dst_user_clean": dst_user_clean
            }
    )