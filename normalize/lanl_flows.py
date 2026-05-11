from __future__ import annotations
from typing import Optional
from datetime import datetime, timezone

from schema import NormalizedEvent, new_event_id


def normalize_lanl_flow_line(line: str) -> Optional[NormalizedEvent]:
    parts = line.strip().split(",")

    if len(parts) != 9:
        return None

    ts, duration, src_computer, src_port, dst_computer, dst_port, protocol, packets, bytes_count = parts

    return NormalizedEvent(
        event_id=new_event_id(),
        timestamp=datetime.now(timezone.utc).isoformat(),
        source="lanl_flows",
        event_type="lanl_network_flow",
        outcome="observed",
        host=src_computer,
        src_port=None if src_port.startswith("N") else int(src_port) if src_port.isdigit() else None,
        dest_port=None if dst_port.startswith("N") else int(dst_port) if dst_port.isdigit() else None,
        message=line.strip(),
        raw_log=line.strip(),
        tags=["lanl", "network", "flow"],
        extra={
            "lanl_time": ts,
            "duration": duration,
            "src_computer": src_computer,
            "src_port": src_port,
            "dst_computer": dst_computer,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_count": packets,
            "byte_count": bytes_count
        }
    )