from __future__ import annotations
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Any, Dict, Optional
import uuid

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def new_event_id() -> str:
    return str(uuid.uuid4())

@dataclass
class NormalizedEvent:
    event_id: str
    timestamp: str                 # ISO 8601
    source: str                    # "authlog" | "honeypot"
    event_type: str                # e.g., "ssh_invalid_user"
    outcome: Optional[str] = None  # success/failure/unknown
    host: Optional[str] = None
    user: Optional[str] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_ip: Optional[str] = None
    dest_port: Optional[int] = None
    program: Optional[str] = None
    pid: Optional[int] = None
    message: Optional[str] = None
    tags: Optional[list[str]] = None
    raw_log: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None  # any leftover structured fields

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # remove None for cleaner JSONL
        return {k: v for k, v in d.items() if v is not None}