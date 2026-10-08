#!/usr/bin/env python3
"""bcurl -- a BHTP/1 client (see SPEC.md).

    ./bcurl -v localhost:9000/index.html
    ./bcurl localhost:9000/index.html /style.css /missing.html   # one connection

Builds binary REQUEST frames, reads the response, writes the body to stdout.
-v hexdumps every frame (both directions) to stderr.
Exit status: 0 success, 4 if any response was 4xx, 5 if any was 5xx,
2 for connection/protocol failures. Never opens a second connection.
"""

import argparse
import socket
import sys

import bproto as bp

USER_AGENT = "bcurl/1.0"
EXIT_OK, EXIT_PROTOCOL, EXIT_4XX, EXIT_5XX = 0, 2, 4, 5


def parse_target(text):
    """'localhost:9000/index.html' -> ('localhost', 9000, '/index.html')."""
    if "://" in text:
        text = text.split("://", 1)[1]
    hostport, slash, path = text.partition("/")
    path = "/" + path if slash else "/"
    host, colon, port = hostport.rpartition(":")
    if not colon:
        host, port = hostport, "9000"
    if not host or not port.isdigit():
        raise ValueError("expected host:port/path, got %r" % text)
    return host, int(port), path


class Client:
    def __init__(self, host, port, verbose=False, out=None, timeout=10.0):
        self.host = host
        self.port = port
        self.verbose = verbose
        self.out = out or sys.stderr
        self.next_id = 1
        self.sock = socket.create_connection((host, port), timeout=timeout)
        self.reader = bp.FrameReader(self.sock, on_frame=self._dump_in)
        self._send(bp.PREFACE, preface=True)

    def _log(self, text):
        print(text, file=self.out, flush=True)

    def _dump(self, arrow, data, payload=None, skipped=0):
        header = data[:bp.HEADER_SIZE]
        lines = bp.describe_frame(header, data[bp.HEADER_SIZE:] if payload is None else payload,
                                  skipped)
        self._log("%s %s" % (arrow, lines[0]))
        for line in lines[1:]:
            self._log("%s %s" % (arrow, line))
        shown = data if payload is None else header + payload
        self._log(bp.hexdump(shown, indent="%s   " % arrow))

    def _dump_in(self, header, payload, skipped):
        if self.verbose:
            if payload is None:
                self._dump("<", header, None, skipped)
                self._log("<   (unknown type or oversize: skipped, still in sync)")
            else:
                self._dump("<", header + payload)

    def _send(self, data, preface=False):
        if self.verbose:
            if preface:
                self._log("> PREFACE %r" % data)
                self._log(bp.hexdump(data, indent=">   "))
            else:
                offset = 0
                while offset < len(data):
                    length = bp.decode_frame_header(data[offset:offset + bp.HEADER_SIZE])[0]
                    end = offset + bp.HEADER_SIZE + length
                    self._dump(">", data[offset:end])
                    offset = end
        self.sock.sendall(data)

    def build_request(self, path, close=False, send_unknown=False):
        request_id = self.next_id
        self.next_id += 1
        extra = [("user-agent", USER_AGENT), ("accept", "*/*")]
        if close:
            extra.append(("connection", "close"))
        data = b""
        if send_unknown:
            data += bp.encode_frame(0x7F, 0, request_id, b"v2 feature the server has never heard of")
        host_header = "%s:%d" % (self.host, self.port)
        data += bp.encode_request(request_id, path, host_header, extra)
        return request_id, data

    def read_response(self, request_id):
        """Return (status, headers, body) for request_id."""
        status = headers = None
        body = bytearray()
        while True:
            frame = self.reader.read_frame()
            if frame.payload is None:
                continue  # unknown type (or oversize): skipped cleanly, per SPEC 4.
            if frame.type == bp.TYPE_GOAWAY:
                raise bp.ProtocolError("server sent GOAWAY before answering request %d"
                                       % request_id)
            if frame.request_id != request_id:
                raise bp.ProtocolError("expected frames for id %d, got id %d"
                                       % (request_id, frame.request_id))
            if frame.type == bp.TYPE_RESPONSE:
                status, headers = bp.decode_response_payload(frame.payload)
                if frame.end_stream:
                    return status, headers, bytes(body)
            elif frame.type == bp.TYPE_DATA:
                if status is None:
                    raise bp.ProtocolError("DATA before RESPONSE")
                body.extend(frame.payload)
                if frame.end_stream:
                    return status, headers, bytes(body)
            else:
                raise bp.ProtocolError("unexpected %s frame" % frame.type_name)

    def close(self):
        self.sock.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description="BHTP/1 client")
    parser.add_argument("-v", "--verbose", action="store_true", help="hexdump every frame")
    parser.add_argument("-o", "--output", help="write body to this file instead of stdout")
    parser.add_argument("--pipeline", action="store_true",
                        help="send every request before reading any response")
    parser.add_argument("--close", action="store_true",
                        help="send connection: close on the last request")
    parser.add_argument("--send-unknown", action="store_true",
                        help="precede each request with an unknown frame type (tests skipping)")
    parser.add_argument("url", help="host:port/path")
    parser.add_argument("more", nargs="*", help="more /paths (or host:port/paths) on the SAME connection")
    args = parser.parse_args(argv)

    try:
        host, port, first_path = parse_target(args.url)
        paths = [first_path]
        for extra in args.more:
            if extra.startswith("/"):
                paths.append(extra)
                continue
            h, p, path = parse_target(extra)
            if (h, p) != (host, port):
                parser.error("%s is a different server; bcurl never opens a second connection"
                             % extra)
            paths.append(path)
    except ValueError as error:
        parser.error(str(error))

    out = open(args.output, "wb") if args.output else sys.stdout.buffer
    worst = EXIT_OK
    try:
        client = Client(host, port, verbose=args.verbose)
    except OSError as error:
        print("bcurl: cannot connect to %s:%d: %s" % (host, port, error), file=sys.stderr)
        return EXIT_PROTOCOL

    try:
        requests = []
        for i, path in enumerate(paths):
            close = args.close and i == len(paths) - 1
            requests.append((path,) + client.build_request(path, close, args.send_unknown))
        if args.pipeline:
            client._send(b"".join(data for _, _, data in requests))
        for path, request_id, data in requests:
            if not args.pipeline:
                client._send(data)
            status, headers, body = client.read_response(request_id)
            if args.verbose:
                print("* %s -> %d (%d body bytes)" % (path, status, len(body)),
                      file=sys.stderr, flush=True)
            out.write(body)
            out.flush()
            if 400 <= status < 500:
                worst = max(worst, EXIT_4XX)
            elif status >= 500:
                worst = max(worst, EXIT_5XX)
        if args.verbose:
            print("* %d request(s) on 1 connection" % len(paths), file=sys.stderr)
    except (bp.ProtocolError, bp.ConnectionClosed, OSError) as error:
        print("bcurl: %s" % error, file=sys.stderr)
        return EXIT_PROTOCOL
    finally:
        client.close()
        if args.output:
            out.close()
    return worst


if __name__ == "__main__":
    sys.exit(main())
