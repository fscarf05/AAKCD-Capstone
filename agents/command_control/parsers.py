import json


def load_events(path):
    return [_normalise(row) for row in _read_rows(path)]


def _read_rows(path):
    with open(path, "r", errors="replace") as handle:
        first_line = handle.readline()
        handle.seek(0)

        if first_line.lstrip().startswith("{"):
            for line in handle:
                if line.strip():
                    yield json.loads(line)
            return

        fields = None
        for line in handle:
            line = line.rstrip("\n")
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#") or not line.strip():
                continue
            if fields is None:
                raise ValueError(
                    f"{path} has no #fields header and is not JSON. "
                    "Is this a Zeek conn.log?"
                )
            yield dict(zip(fields, line.split("\t")))


def _number(value, default=0.0):
    try:
        if value in ("-", "", None):
            return default
        return float(value)
    except (TypeError, ValueError):
        return default


def _normalise(row):

    def field(zeek_name, alt_name, plain_name):
        for name in (zeek_name, alt_name, plain_name):
            if name in row:
                return row[name]
        return None

    return {
        "timestamp": _number(row.get("ts", row.get("timestamp"))),
        "source_ip": field("id.orig_h", "id_orig_h", "source_ip"),
        "source_port": int(_number(field("id.orig_p", "id_orig_p", "source_port"))),
        "destination_ip": field("id.resp_h", "id_resp_h", "destination_ip"),
        "destination_port": int(_number(field("id.resp_p", "id_resp_p", "destination_port"))),
        "protocol": row.get("proto", row.get("protocol", "-")),
        "service": row.get("service", "-"),
        "duration": _number(row.get("duration")),
        "bytes_out": _number(row.get("orig_bytes", row.get("bytes_out"))),
        "bytes_in": _number(row.get("resp_bytes", row.get("bytes_in"))),
    }