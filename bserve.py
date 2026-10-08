#!/usr/bin/env python3
"""bserve -- a static file server that speaks BHTP/1 (see SPEC.md).

    ./bserve ./www 9000

Accepts TCP connections, reads binary REQUEST frames, maps :path to a file
under the root, replies with a RESPONSE frame plus DATA frames, and keeps the
connection open for the next request.
"""

import argparse
import email.utils
import mimetypes
import os
import socket
import sys
import threading
import time
from urllib.parse import unquote

import bproto as bp

SERVER_NAME = "bserve/1.0"
# Longer than the calculator's 15 s: BHTP clients are often being debugged by hand,
# frame by frame. Still bounded, because each open connection holds a thread.
DEFAULT_IDLE_TIMEOUT = 30.0


class BServe:
    def __init__(self, root, host="127.0.0.1", port=9000, idle_timeout=DEFAULT_IDLE_TIMEOUT,
                 log=True, emit_unknown=False):
        self.root = os.path.realpath(root)
        self.host = host
        self.port = port
        self.idle_timeout = idle_timeout
        self.log_enabled = log
        self.emit_unknown = emit_unknown
        self.connections_accepted = 0
        self._sock = None
        self._lock = threading.Lock()

    def log(self, message):
        if self.log_enabled:
            print("[%s] %s" % (time.strftime("%H:%M:%S"), message), flush=True)

    def bind(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, self.port))
        self._sock.listen(64)
        self.port = self._sock.getsockname()[1]
        return self.port

    def serve_forever(self):
        if self._sock is None:
            self.bind()
        self.log("bserve serving %s on %s:%d (BHTP/1, idle timeout %.0fs)"
                 % (self.root, self.host, self.port, self.idle_timeout))
        while True:
            try:
                client, address = self._sock.accept()
            except OSError:
                break
            with self._lock:
                self.connections_accepted += 1
                conn_id = self.connections_accepted
            threading.Thread(target=self._serve, args=(client, address, conn_id),
                             daemon=True).start()

    def shutdown(self):
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass

    # ------------------------------------------------------------ files

    def resolve(self, path):
        """Map a :path to a real file under root, or None (-> 404)."""
        path = path.split("?", 1)[0].split("#", 1)[0]
        segments = [unquote(s) for s in path.split("/")]
        if any(s in ("..", ".") or "/" in s or "\\" in s or "\x00" in s for s in segments):
            return None
        candidate = os.path.realpath(os.path.join(self.root, *[s for s in segments if s]))
        if candidate != self.root and not candidate.startswith(self.root + os.sep):
            return None
        if os.path.isdir(candidate):
            candidate = os.path.join(candidate, "index.html")
        return candidate if os.path.isfile(candidate) else None

    def respond(self, sock, request_id, status, body, content_type="text/plain; charset=utf-8",
                extra=()):
        headers = [("server", SERVER_NAME), ("content-type", content_type),
                   ("content-length", str(len(body)))] + list(extra)
        out = bytearray(bp.encode_response(request_id, status, headers, end_stream=not body))
        if self.emit_unknown:
            out += bp.encode_frame(0x7E, 0, request_id, b"future extension, please skip me")
        if body:
            for frame in bp.encode_data_frames(request_id, body):
                out += frame
        sock.sendall(out)

    def error(self, sock, request_id, status, message):
        reason = {400: "Bad Request", 404: "Not Found", 405: "Method Not Allowed",
                  500: "Internal Server Error"}.get(status, "")
        body = ("%d %s: %s\n" % (status, reason, message)).encode("utf-8")
        self.respond(sock, request_id, status, body)
        return status

    def handle(self, sock, request_id, headers):
        if request_id == 0:
            # SPEC 2: ID 0 is the connection's own. Answer on 0 so the client can match it.
            return self.error(sock, 0, 400, "request id 0 is reserved")
        fields = {}
        for name, value in headers:
            if name.startswith(":") and name in fields:
                return self.error(sock, request_id, 400, "duplicate %s" % name)
            fields.setdefault(name, value)
        method = fields.get(":method")
        path = fields.get(":path")
        if not method or not path or not path.startswith("/"):
            return self.error(sock, request_id, 400, "REQUEST needs :method and an absolute :path")
        if method != "GET":
            return self.error(sock, request_id, 405, "only GET is supported")
        filename = self.resolve(path)
        if filename is None:
            return self.error(sock, request_id, 404, "%s is not there" % path)
        try:
            with open(filename, "rb") as handle:
                body = handle.read()
        except OSError as error:
            return self.error(sock, request_id, 500, "cannot read %s (%s)" % (path, error.strerror))
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        if content_type.startswith("text/"):
            content_type += "; charset=utf-8"
        modified = email.utils.formatdate(os.path.getmtime(filename), usegmt=True)
        self.respond(sock, request_id, 200, body, content_type, [("last-modified", modified)])
        return 200

    # ------------------------------------------------------------ connection loop

    def _serve(self, sock, address, conn_id):
        sock.settimeout(self.idle_timeout)
        reader = bp.FrameReader(sock)
        served = 0
        reason = "?"
        pending = None  # (request_id, headers_or_error_string) waiting for END_STREAM
        self.log("conn #%d open from %s:%d" % (conn_id, address[0], address[1]))

        def finish(request_id, parsed):
            nonlocal served
            if isinstance(parsed, str):
                status = self.error(sock, request_id, 400, parsed)
                label = "<malformed: %s>" % parsed
            else:
                status = self.handle(sock, request_id, parsed)
                label = "%s %s" % (dict(parsed).get(":method"), dict(parsed).get(":path"))
            served += 1
            self.log("conn #%d  id=%d %s -> %d" % (conn_id, request_id, label, status))
            return not isinstance(parsed, str) and dict(parsed).get("connection") == "close"

        try:
            if reader.read_exact(len(bp.PREFACE), at_boundary=True) != bp.PREFACE:
                sock.sendall(bp.encode_goaway(bp.GOAWAY_PROTOCOL_ERROR, "bad preface"))
                reason = "bad connection preface"
                return
            while True:
                frame = reader.read_frame()
                if frame.payload is None:
                    if frame.type not in bp.TYPE_NAMES:
                        self.log("conn #%d  skipped unknown frame type 0x%02x"
                                 % (conn_id, frame.type))
                        continue
                    # Known type but over MAX_PAYLOAD: its bytes are already skipped,
                    # so we are still in sync and can answer 400.
                    too_big = "frame larger than %d bytes" % bp.MAX_PAYLOAD
                    if frame.type == bp.TYPE_REQUEST:
                        pending = (frame.request_id, too_big)
                    elif frame.type == bp.TYPE_DATA and pending and pending[0] == frame.request_id:
                        pending = (frame.request_id, too_big)
                    else:
                        continue
                    if frame.end_stream:
                        finish(*pending)
                        pending = None
                    continue

                if frame.type == bp.TYPE_REQUEST:
                    if pending:
                        finish(pending[0], "REQUEST arrived before previous END_STREAM")
                        pending = None
                    try:
                        parsed = bp.decode_headers(frame.payload)
                    except bp.ProtocolError as error:
                        parsed = str(error)
                    if frame.end_stream:
                        if finish(frame.request_id, parsed):
                            sock.sendall(bp.encode_goaway(bp.GOAWAY_NO_ERROR, "connection: close"))
                            reason = "client asked for connection: close"
                            return
                    else:
                        pending = (frame.request_id, parsed)

                elif frame.type == bp.TYPE_DATA:
                    if not pending or frame.request_id != pending[0]:
                        finish(frame.request_id, "DATA for a request that is not open")
                        continue
                    if frame.end_stream:  # GET ignores the body; we only needed its end.
                        request_id, parsed = pending
                        pending = None
                        if finish(request_id, parsed):
                            sock.sendall(bp.encode_goaway(bp.GOAWAY_NO_ERROR, "connection: close"))
                            reason = "client asked for connection: close"
                            return

                elif frame.type == bp.TYPE_GOAWAY:
                    reason = "client sent GOAWAY"
                    return

                elif frame.type == bp.TYPE_RESPONSE:
                    finish(frame.request_id, "clients do not send RESPONSE frames")

        except bp.ConnectionClosed as closed:
            reason = "client closed" + ("" if closed.clean else " mid-frame")
        except socket.timeout:
            reason = "idle for %.0fs" % self.idle_timeout
            try:
                sock.sendall(bp.encode_goaway(bp.GOAWAY_IDLE_TIMEOUT, "idle timeout"))
            except OSError:
                pass
        except (ConnectionResetError, ConnectionAbortedError, BrokenPipeError):
            reason = "connection reset"
        finally:
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            sock.close()
            self.log("conn #%d closed after %d request(s): %s" % (conn_id, served, reason))


def main(argv=None):
    parser = argparse.ArgumentParser(description="BHTP/1 static file server")
    parser.add_argument("root", help="directory to serve, e.g. ./www")
    parser.add_argument("port", type=int, nargs="?", default=9000)
    parser.add_argument("--host", default="127.0.0.1",
                        help="interface to bind (use 0.0.0.0 to accept other machines)")
    parser.add_argument("--idle-timeout", type=float, default=DEFAULT_IDLE_TIMEOUT)
    parser.add_argument("--emit-unknown", action="store_true",
                        help="send an unknown frame type before each body (tests client skipping)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)
    if not os.path.isdir(args.root):
        parser.error("%s is not a directory" % args.root)
    server = BServe(args.root, args.host, args.port, args.idle_timeout,
                    log=not args.quiet, emit_unknown=args.emit_unknown)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down", file=sys.stderr)
        server.shutdown()


if __name__ == "__main__":
    main()
