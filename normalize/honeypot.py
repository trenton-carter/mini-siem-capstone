from __future__ import annotations
import json
from datetime import datetime, timezone
from typing import Any, Optional, Dict

from schema import NormalizedEvent, new_event_id

def _parse_mongo_date(obj: Any) -> Optional[str]:
    if isinstance(obj, dict) and "$date" in obj:
        s = obj["$date"]
        try:
            dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z")
        except ValueError:
            dt = datetime.strptime(s, "%Y-%m-%dT%H:%M:%S%z")
        return dt.astimezone(timezone.utc).isoformat()
    return None

def _safe_int(x: Any) -> Optional[int]:
    try:
        return int(x)
    except Exception:
        return None

def normalize_honeypot_line(line: str) -> NormalizedEvent:
    doc = json.loads(line)

    ts = _parse_mongo_date(doc.get("timestamp")) or datetime.now(timezone.utc).isoformat()
    channel = doc.get("channel", "honeypot")
    payload_raw = doc.get("payload")

    extra: Dict[str, Any] = {"channel": channel, "ident": doc.get("ident")}
    src_ip = None
    src_port = None
    event_type = "honeypot_event"
    outcome = "unknown"
    message = None
    tags = ["honeypot"]

    payload_obj = None
    if isinstance(payload_raw, str):
        try:
            payload_obj = json.loads(payload_raw)
        except Exception:
            extra["payload_parse_error"] = True
    elif isinstance(payload_raw, dict):
        payload_obj = payload_raw

    if isinstance(payload_obj, dict):
        # glastopf format
        if "source" in payload_obj and isinstance(payload_obj["source"], list) and len(payload_obj["source"]) >= 2:
            src_ip = payload_obj["source"][0]
            src_port = _safe_int(payload_obj["source"][1])
            event_type = "http_request"
            tags += ["http"]
            message = payload_obj.get("request_url")

        # amun format
        if "attackerIP" in payload_obj:
            src_ip = payload_obj.get("attackerIP")
            src_port = _safe_int(payload_obj.get("attackerPort"))
            extra["victimIP"] = payload_obj.get("victimIP")
            extra["victimPort"] = payload_obj.get("victimPort")
            event_type = "amun_connection"
            tags += ["connection"]

        req_raw = payload_obj.get("request_raw", "")
        if isinstance(req_raw, str) and ("wget " in req_raw or "curl " in req_raw or "bash" in req_raw):
            tags += ["suspicious", "command_injection"]

        pattern = payload_obj.get("pattern")
        if pattern:
            tags.append(f"pattern:{pattern}")

        # keep a few useful fields
        extra["payload"] = {k: payload_obj.get(k) for k in ["pattern", "request_url", "time"] if k in payload_obj}

    return NormalizedEvent(
        event_id=new_event_id(),
        timestamp=ts,
        source="honeypot",
        event_type=event_type,
        outcome=outcome,
        src_ip=src_ip,
        src_port=src_port,
        message=message,
        tags=tags,
        raw_log=line,
        extra=extra,
    )