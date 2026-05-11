import json

def read_lines(path, source=None, encoding="utf-8"):
    """Read a plain text file and yield (line, metadata)."""
    with open(path, "r", encoding=encoding, errors="replace") as f:
        for line in f:
            line = line.rstrip("\n").rstrip("\r")
            if not line.strip():
                continue
            yield line, {"source": source}


def read_json_lines(path):
    """Read a JSON-per-line file."""
    events = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            events.append(json.loads(line))
    return events