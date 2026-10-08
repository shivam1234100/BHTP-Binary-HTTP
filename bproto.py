"""BHTP/1 -- the wire format shared by bserve and bcurl. See SPEC.md.

Frame header, 8 bytes, big-endian:

     0                   1                   2                   3
     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-----------------------------------------------+---------------+
    |                 Length (24)                   |   Type (8)    |
    +---------------+-------------------------------+---------------+
    |   Flags (8)   |              Request ID (24)                  |
    +---------------+-----------------------------------------------+
    |                    Payload (Length bytes) ...
"""

import struct

PREFACE = b"BHTP/1\r\n"
HEADER_SIZE = 8
MAX_PAYLOAD = 16384
MAX_REQUEST_ID = (1 << 24) - 1

TYPE_REQUEST = 0x01
TYPE_RESPONSE = 0x02
TYPE_DATA = 0x03
TYPE_GOAWAY = 0x04
TYPE_NAMES = {
    TYPE_REQUEST: "REQUEST",
    TYPE_RESPONSE: "RESPONSE",
    TYPE_DATA: "DATA",
    TYPE_GOAWAY: "GOAWAY",
}

FLAG_END_STREAM = 0x01

GOAWAY_NO_ERROR = 0x0000
GOAWAY_PROTOCOL_ERROR = 0x0001
GOAWAY_IDLE_TIMEOUT = 0x0002
GOAWAY_NAMES = {0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "IDLE_TIMEOUT"}

# The ten header names we actually send, 1-based. Index 0x00 means "literal name follows".
STATIC_TABLE = [
    None,
    ":method",         # 0x01
    ":path",           # 0x02
    "host",            # 0x03
    "user-agent",      # 0x04
    "accept",          # 0x05
    "connection",      # 0x06
    "server",          # 0x07
    "content-type",    # 0x08
    "content-length",  # 0x09
    "last-modified",   # 0x0A
]
STATIC_INDEX = {name: i for i, name in enumerate(STATIC_TABLE) if name}
LITERAL_NAME = 0x00


class ProtocolError(Exception):
    """The peer sent bytes that violate SPEC.md."""


class ConnectionClosed(Exception):
    """EOF. clean=True means it happened exactly on a frame boundary."""

    def __init__(self, clean):
        super().__init__("connection closed" + ("" if clean else " mid-frame"))
        self.clean = clean


class Frame:
    __slots__ = ("type", "flags", "request_id", "payload")

    def __init__(self, ftype, flags, request_id, payload=b""):
        self.type = ftype
        self.flags = flags
        self.request_id = request_id
        self.payload = payload

    @property
    def end_stream(self):
        return bool(self.flags & FLAG_END_STREAM)

    @property
    def type_name(self):
        return TYPE_NAMES.get(self.type, "UNKNOWN(0x%02x)" % self.type)

    def encode(self):
        return encode_frame(self.type, self.flags, self.request_id, self.payload)


def encode_frame_header(length, ftype, flags, request_id):
    if not 0 <= length < (1 << 24):
        raise ValueError("length out of range")
    if not 0 <= request_id <= MAX_REQUEST_ID:
        raise ValueError("request id out of range")
    return struct.pack(">I", (length << 8) | ftype) + struct.pack(">I", (flags << 24) | request_id)


def decode_frame_header(data):
    if len(data) != HEADER_SIZE:
        raise ValueError("frame header is exactly 8 bytes")
    word0, word1 = struct.unpack(">II", data)
    return word0 >> 8, word0 & 0xFF, word1 >> 24, word1 & 0xFFFFFF


def encode_frame(ftype, flags, request_id, payload=b""):
    return encode_frame_header(len(payload), ftype, flags, request_id) + payload


# ---------------------------------------------------------------- header block

def encode_headers(headers):
    """headers: list of (name, value) str pairs -> bytes."""
    out = bytearray()
    for name, value in headers:
        name = name.lower()
        value_bytes = value.encode("utf-8")
        if len(value_bytes) > 0xFFFF:
            raise ValueError("header value too long")
        index = STATIC_INDEX.get(name)
        if index is not None:
            out.append(index)
        else:
            name_bytes = name.encode("ascii")
            if not 1 <= len(name_bytes) <= 255:
                raise ValueError("header name must be 1..255 bytes")
            out.append(LITERAL_NAME)
            out.append(len(name_bytes))
            out.extend(name_bytes)
        out.extend(struct.pack(">H", len(value_bytes)))
        out.extend(value_bytes)
    return bytes(out)


def decode_headers(block):
    """bytes -> list of (name, value). Raises ProtocolError on any malformation."""
    headers = []
    pos = 0
    end = len(block)
    while pos < end:
        tag = block[pos]
        pos += 1
        if tag == LITERAL_NAME:
            if pos >= end:
                raise ProtocolError("truncated literal name length")
            name_len = block[pos]
            pos += 1
            if name_len == 0 or pos + name_len > end:
                raise ProtocolError("bad literal name length")
            try:
                name = block[pos:pos + name_len].decode("ascii")
            except UnicodeDecodeError:
                raise ProtocolError("header name is not ASCII")
            if name != name.lower():
                raise ProtocolError("header names must be lower-case")
            pos += name_len
        elif tag < len(STATIC_TABLE):
            name = STATIC_TABLE[tag]
        else:
            raise ProtocolError("unknown header index 0x%02x" % tag)
        if pos + 2 > end:
            raise ProtocolError("truncated value length")
        (value_len,) = struct.unpack(">H", block[pos:pos + 2])
        pos += 2
        if pos + value_len > end:
            raise ProtocolError("value runs past end of header block")
        try:
            value = block[pos:pos + value_len].decode("utf-8")
        except UnicodeDecodeError:
            raise ProtocolError("header value is not UTF-8")
        pos += value_len
        headers.append((name, value))
    return headers


def encode_request(request_id, path, host, extra=(), end_stream=True):
    headers = [(":method", "GET"), (":path", path), ("host", host)] + list(extra)
    flags = FLAG_END_STREAM if end_stream else 0
    return encode_frame(TYPE_REQUEST, flags, request_id, encode_headers(headers))


def encode_response(request_id, status, headers, end_stream):
    payload = struct.pack(">H", status) + encode_headers(headers)
    return encode_frame(TYPE_RESPONSE, FLAG_END_STREAM if end_stream else 0, request_id, payload)


def decode_response_payload(payload):
    if len(payload) < 2:
        raise ProtocolError("RESPONSE payload shorter than status field")
    (status,) = struct.unpack(">H", payload[:2])
    return status, decode_headers(payload[2:])


def encode_goaway(code, reason=""):
    return encode_frame(TYPE_GOAWAY, 0, 0, struct.pack(">H", code) + reason.encode("utf-8"))


def encode_data_frames(request_id, body):
    """Split body into DATA frames of at most MAX_PAYLOAD; last carries END_STREAM."""
    frames = []
    if not body:
        return [encode_frame(TYPE_DATA, FLAG_END_STREAM, request_id, b"")]
    for start in range(0, len(body), MAX_PAYLOAD):
        chunk = body[start:start + MAX_PAYLOAD]
        last = start + MAX_PAYLOAD >= len(body)
        frames.append(encode_frame(TYPE_DATA, FLAG_END_STREAM if last else 0, request_id, chunk))
    return frames


# ---------------------------------------------------------------- reading

class FrameReader:
    """Pulls whole frames off a socket. Exactly Length bytes per frame: never more."""

    def __init__(self, sock, on_frame=None):
        self.sock = sock
        self.buffer = bytearray()
        self.on_frame = on_frame  # callback(header_bytes, payload_bytes_or_None, skipped)

    def _fill(self, at_boundary):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise ConnectionClosed(clean=at_boundary and not self.buffer)
        self.buffer.extend(chunk)

    def read_exact(self, n, at_boundary=False):
        while len(self.buffer) < n:
            self._fill(at_boundary)
        data = bytes(self.buffer[:n])
        del self.buffer[:n]
        return data

    def discard(self, n):
        """Throw away n bytes without holding them all in memory."""
        while n > 0:
            if not self.buffer:
                self._fill(at_boundary=False)
            take = min(n, len(self.buffer))
            del self.buffer[:take]
            n -= take

    def read_frame(self, max_payload=MAX_PAYLOAD, known_types=TYPE_NAMES):
        """Return a Frame. Unknown types and oversize frames come back with
        payload=None after their bytes have been skipped, so the caller stays in sync."""
        header = self.read_exact(HEADER_SIZE, at_boundary=True)
        length, ftype, flags, request_id = decode_frame_header(header)
        if ftype not in known_types or length > max_payload:
            self.discard(length)
            if self.on_frame:
                self.on_frame(header, None, length)
            return Frame(ftype, flags, request_id, None)
        payload = self.read_exact(length)
        if self.on_frame:
            self.on_frame(header, payload, 0)
        return Frame(ftype, flags, request_id, payload)


# ---------------------------------------------------------------- debugging

def hexdump(data, indent="    "):
    lines = []
    for offset in range(0, len(data), 16):
        row = data[offset:offset + 16]
        hex_part = " ".join("%02x" % b for b in row[:8])
        if len(row) > 8:
            hex_part += "  " + " ".join("%02x" % b for b in row[8:])
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in row)
        lines.append("%s%04x  %-49s |%s|" % (indent, offset, hex_part, text))
    return "\n".join(lines)


def describe_frame(header, payload, skipped=0):
    """One-line summary plus decoded payload, for -v output."""
    length, ftype, flags, request_id = decode_frame_header(header)
    name = TYPE_NAMES.get(ftype, "UNKNOWN(0x%02x)" % ftype)
    flag_text = "END_STREAM" if flags & FLAG_END_STREAM else "-"
    lines = ["%s len=%d flags=0x%02x(%s) id=%d" % (name, length, flags, flag_text, request_id)]
    if payload is None:
        lines.append("  (skipped %d payload bytes)" % skipped)
        return lines
    try:
        if ftype == TYPE_REQUEST:
            for n, v in decode_headers(payload):
                lines.append("  %s: %s" % (n, v))
        elif ftype == TYPE_RESPONSE:
            status, headers = decode_response_payload(payload)
            lines.append("  status: %d" % status)
            for n, v in headers:
                lines.append("  %s: %s" % (n, v))
        elif ftype == TYPE_GOAWAY and len(payload) >= 2:
            (code,) = struct.unpack(">H", payload[:2])
            lines.append("  code: %s %s" % (GOAWAY_NAMES.get(code, code),
                                            payload[2:].decode("utf-8", "replace")))
    except ProtocolError as error:
        lines.append("  (malformed: %s)" % error)
    return lines
