from __future__ import annotations
import re
from datetime import datetime, timezone
from typing import Optional, Dict, Any

from schema import NormalizedEvent, new_event_id

SYSLOG_RE = re.compile(
    r"^(?P<mon>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+(?P<program>[A-Za-z0-9_\-/.]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<msg>.*)$"
)

RE_INVALID_USER = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_CONN_CLOSED = re.compile(r"Connection closed by (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_NO_IDENT = re.compile(r"Did not receive identification string from (?P<ip>\d+\.\d+\.\d+\.\d+)")
RE_DISCONNECT = re.compile(
    r"Received disconnect from (?P<ip>\d+\.\d+\.\d+\.\d+):\s*(?P<code>\d+):\s*(?P<reason>.*)\s*\[preauth\]"
)
RE_CRON_OPEN = re.compile(r"pam_unix\(cron:session\): session opened for user (?P<user>\S+)")
RE_CRON_CLOSE = re.compile(r"pam_unix\(cron:session\): session closed for user (?P<user>\S+)")
RE_SOCKET_FAIL = re.compile(r"fatal: Read from socket failed: (?P<reason>.*)\s*\[preauth\]")

MONTHS = {"Jan":1,"Feb":2,"Mar":3,"Apr":4,"May":5,"Jun":6,"Jul":7,"Aug":8,"Sep":9,"Oct":10,"Nov":11,"Dec":12}

def _parse_syslog_ts(mon: str, day: str, t: str, year: int) -> str:
    dt = datetime(
        year, MONTHS[mon], int(day),
        int(t[0:2]), int(t[3:5]), int(t[6:8]),
        tzinfo=timezone.utc
    )
    return dt.isoformat()

def normalize_authlog_line(line: str, year: int) -> Optional[NormalizedEvent]:
    m = SYSLOG_RE.match(line)
    if not m:
        return NormalizedEvent(
            event_id=new_event_id(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            source="authlog",
            event_type="unparsed_authlog",
            outcome="unknown",
            raw_log=line,
            message="Line did not match syslog pattern",
        )

    ts = _parse_syslog_ts(m["mon"], m["day"], m["time"], year)
    host = m["host"]
    program = m["program"]
    pid = int(m["pid"]) if m["pid"] else None
    msg = m["msg"]

    mo = RE_CRON_OPEN.search(msg)
    if mo:
        return NormalizedEvent(
            event_id=new_event_id(),
            timestamp=ts,
            source="authlog",
            event_type="cron_session_open",
            outcome="success",
            host=host,
            user=mo["user"],
            program=program,
            pid=pid,
            message=msg,
            raw_log=line,
            tags=["cron", "session"],
        )

    mc = RE_CRON_CLOSE.search(msg)
    if mc:
        return NormalizedEvent(
            event_id=new_event_id(),
            timestamp=ts,
            source="authlog",
            event_type="cron_session_close",
            outcome="success",
            host=host,
            user=mc["user"],
            program=program,
            pid=pid,
            message=msg,
            raw_log=line,
            tags=["cron", "session"],
        )

    miu = RE_INVALID_USER.search(msg)
    if miu:
        return NormalizedEvent(
            event_id=new_event_id(),
            timestamp=ts,
            source="authlog",
            event_type="ssh_invalid_user",
            outcome="failure",
            host=host,
            user=miu["user"],
            src_ip=miu["ip"],
            program=program,
            pid=pid,
            message=msg,
            raw_log=line,
            tags=["ssh", "auth"],
        )

    mcc = RE_CONN_CLOSED.search(msg)
    if mcc:
        return NormalizedEvent(
            event_id=new_event_id(),
            timestamp=ts,
            source="authlog",
            event_type="ssh_connection_closed",
            outcome="unknown",
            host=host,
            src_ip=mcc["ip"],
            program=program,
            pid=pid,
            message=msg,
            raw_log=line,
            tags=["ssh"],
        )

    mni = RE_NO_IDENT.search(msg)
    if mni:
        return NormalizedEvent(
            event_id=new_event_id(),
            timestamp=ts,
            source="authlog",
            event_type="ssh_no_identification",
            outcome="failure",
            host=host,
            src_ip=mni["ip"],
            program=program,
            pid=pid,
            message=msg,
            raw_log=line,
            tags=["ssh", "recon"],
        )

    md = RE_DISCONNECT.search(msg)
    if md:
        return NormalizedEvent(
            event_id=new_event_id(),
            timestamp=ts,
            source="authlog",
            event_type="ssh_disconnect",
            outcome="unknown",
            host=host,
            src_ip=md["ip"],
            program=program,
            pid=pid,
            message=msg,
            raw_log=line,
            extra={"disconnect_code": md["code"], "disconnect_reason": md["reason"].strip()},
            tags=["ssh"],
        )

    msf = RE_SOCKET_FAIL.search(msg)
    if msf:
        return NormalizedEvent(
            event_id=new_event_id(),
            timestamp=ts,
            source="authlog",
            event_type="ssh_socket_error",
            outcome="failure",
            host=host,
            program=program,
            pid=pid,
            message=msg,
            raw_log=line,
            extra={"reason": msf["reason"].strip()},
            tags=["ssh", "error"],
        )

    return NormalizedEvent(
        event_id=new_event_id(),
        timestamp=ts,
        source="authlog",
        event_type="authlog_other",
        outcome="unknown",
        host=host,
        program=program,
        pid=pid,
        message=msg,
        raw_log=line,
        tags=["authlog"],
    )