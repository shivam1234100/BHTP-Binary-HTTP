"""Tests for (bserve / bcurl / BHTP/1). Run from the project root:

    python -m unittest discover -s tests -v

The RawWireTest class deliberately builds bytes by hand from SPEC.md instead of
using bproto's encoders, so it checks the server against the spec, not against
our own client.
"""

import io
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
from contextlib import redirect_stderr
from unittest import mock

HERE = os.path.dirname(os.path.abspath(__file__))
PART2 = os.path.join(HERE, "..")
sys.path.insert(0, PART2)

import bproto as bp  # noqa: E402
import bcurl  # noqa: E402
import bserve  # noqa: E402

WWW = os.path.join(PART2, "www")


def start_server(**kwargs):
    server = bserve.BServe(WWW, "127.0.0.1", 0, log=False, **kwargs)
    server.bind()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


def hand_frame(ftype, flags, request_id, payload):
    """SPEC 2: length(24) type(8) flags(8) request-id(24), big-endian."""
    n = len(payload)
    return bytes([n >> 16 & 0xFF, n >> 8 & 0xFF, n & 0xFF, ftype, flags,
                  request_id >> 16 & 0xFF, request_id >> 8 & 0xFF, request_id & 0xFF]) + payload


def hand_indexed(index, value):
    """SPEC 3: indexed name byte, u16 value length, value."""
    value = value.encode()
    return bytes([index]) + struct.pack(">H", len(value)) + value


def hand_get(request_id, path, extra=b""):
    block = hand_indexed(0x01, "GET") + hand_indexed(0x02, path) + hand_indexed(0x03, "t") + extra
    return hand_frame(0x01, 0x01, request_id, block)


class WireReader:
    """Minimal independent frame parser for the tests."""

    def __init__(self, sock):
        self.sock = sock
        self.buf = b""

    def take(self, n):
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise EOFError
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def frame(self):
        h = self.take(8)
        length = h[0] << 16 | h[1] << 8 | h[2]
        return h[3], h[4], h[5] << 16 | h[6] << 8 | h[7], self.take(length)

    def response(self):
        ftype, flags, rid, payload = self.frame()
        assert ftype == 0x02, "expected RESPONSE, got type %d" % ftype
        status = payload[0] << 8 | payload[1]
        body = b""
        while not flags & 0x01:
            ftype, flags, rid2, chunk = self.frame()
            assert ftype == 0x03 and rid2 == rid
            body += chunk
        return rid, status, body


def is_closed(sock, wait=1.0):
    sock.settimeout(wait)
    try:
        while True:
            if sock.recv(65536) == b"":
                return True
    except socket.timeout:
        return False
    except (ConnectionResetError, ConnectionAbortedError):
        return True


class RawWireTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = start_server()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def connect(self, preface=b"BHTP/1\r\n"):
        sock = socket.create_connection(("127.0.0.1", self.server.port), timeout=3)
        self.addCleanup(sock.close)
        sock.sendall(preface)
        return sock, WireReader(sock)

    def test_get_index(self):
        sock, r = self.connect()
        sock.sendall(hand_get(7, "/index.html"))
        rid, status, body = r.response()
        self.assertEqual((rid, status), (7, 200))
        with open(os.path.join(WWW, "index.html"), "rb") as f:
            self.assertEqual(body, f.read())

    def test_directory_maps_to_index_html(self):
        sock, r = self.connect()
        sock.sendall(hand_get(1, "/docs/"))
        self.assertEqual(r.response()[1], 200)

    def test_404_then_connection_still_usable(self):
        sock, r = self.connect()
        sock.sendall(hand_get(1, "/nope.html") + hand_get(2, "/style.css"))
        self.assertEqual(r.response()[:2], (1, 404))
        self.assertEqual(r.response()[:2], (2, 200))

    def test_path_traversal_is_404(self):
        sock, r = self.connect()
        for i, path in enumerate(["/../bproto.py", "/%2e%2e/bproto.py", "/docs/../../bserve.py",
                                  "/..%2fbserve.py"], start=1):
            sock.sendall(hand_get(i, path))
            self.assertEqual(r.response()[1], 404, path)

    def test_malformed_header_block_is_400_and_stays_open(self):
        sock, r = self.connect()
        bad = hand_frame(0x01, 0x01, 1, b"\x02\x00\xff/x")  # value length runs past the end
        sock.sendall(bad + hand_get(2, "/style.css"))
        self.assertEqual(r.response()[:2], (1, 400))
        self.assertEqual(r.response()[:2], (2, 200))

    def test_unknown_header_index_is_400(self):
        sock, r = self.connect()
        sock.sendall(hand_frame(0x01, 0x01, 1, b"\x0b\x00\x01x"))
        self.assertEqual(r.response()[1], 400)

    def test_missing_path_is_400(self):
        sock, r = self.connect()
        sock.sendall(hand_frame(0x01, 0x01, 1, hand_indexed(0x01, "GET")))
        self.assertEqual(r.response()[1], 400)

    def test_non_get_is_405(self):
        sock, r = self.connect()
        block = hand_indexed(0x01, "POST") + hand_indexed(0x02, "/index.html")
        sock.sendall(hand_frame(0x01, 0x01, 1, block))
        self.assertEqual(r.response()[1], 405)

    def test_request_id_zero_is_400_on_id_zero_and_stays_open(self):
        sock, r = self.connect()
        sock.sendall(hand_get(0, "/index.html") + hand_get(1, "/style.css"))
        rid, status, body = r.response()
        self.assertEqual((rid, status), (0, 400))
        self.assertIn(b"request id 0", body)
        self.assertEqual(r.response()[:2], (1, 200))

    def test_unreadable_file_is_500_and_stays_open(self):
        sock, r = self.connect()
        with mock.patch.object(bserve, "open", create=True,
                               side_effect=PermissionError(13, "Permission denied")):
            sock.sendall(hand_get(1, "/style.css"))
            self.assertEqual(r.response()[:2], (1, 500))
        sock.sendall(hand_get(2, "/style.css"))
        self.assertEqual(r.response()[:2], (2, 200))

    def test_unknown_frame_types_are_skipped(self):
        sock, r = self.connect()
        junk = b"".join(hand_frame(t, 0xFF, 1, bytes(range(256)) * 3) for t in (0x00, 0x05, 0xFF))
        sock.sendall(junk + hand_get(1, "/style.css"))
        self.assertEqual(r.response()[:2], (1, 200))

    def test_huge_unknown_frame_is_skipped_without_buffering(self):
        sock, r = self.connect()
        payload = b"\xaa" * 3_000_000
        sock.sendall(hand_frame(0x42, 0, 0, payload) + hand_get(1, "/style.css"))
        self.assertEqual(r.response()[:2], (1, 200))

    def test_oversize_request_frame_is_skipped_with_400(self):
        sock, r = self.connect()
        big = hand_indexed(0x01, "GET") + hand_indexed(0x02, "/" + "a" * 20000)
        sock.sendall(hand_frame(0x01, 0x01, 1, big) + hand_get(2, "/style.css"))
        self.assertEqual(r.response()[:2], (1, 400))
        self.assertEqual(r.response()[:2], (2, 200))

    def test_request_with_body_waits_for_end_stream(self):
        sock, r = self.connect()
        block = hand_indexed(0x01, "GET") + hand_indexed(0x02, "/style.css")
        sock.sendall(hand_frame(0x01, 0x00, 1, block) + hand_frame(0x03, 0x00, 1, b"abc")
                     + hand_frame(0x09, 0, 1, b"?") + hand_frame(0x03, 0x01, 1, b"def"))
        self.assertEqual(r.response()[:2], (1, 200))

    def test_data_for_unopened_request_is_400(self):
        sock, r = self.connect()
        sock.sendall(hand_frame(0x03, 0x01, 9, b"stray"))
        self.assertEqual(r.response()[:2], (9, 400))

    def test_literal_header_names_are_accepted(self):
        sock, r = self.connect()
        literal = b"\x00\x05x-foo" + struct.pack(">H", 3) + b"bar"
        sock.sendall(hand_get(1, "/style.css", extra=literal))
        self.assertEqual(r.response()[1], 200)

    def test_dribbled_bytes(self):
        sock, r = self.connect()
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        for b in hand_get(3, "/style.css"):
            sock.send(bytes([b]))
        self.assertEqual(r.response()[:2], (3, 200))

    def test_bad_preface_gets_goaway_and_close(self):
        sock, r = self.connect(preface=b"GET / HTTP/1.1\r\n\r\n")
        ftype, _, rid, payload = r.frame()
        self.assertEqual((ftype, rid, payload[:2]), (0x04, 0, b"\x00\x01"))
        self.assertTrue(is_closed(sock))

    def test_connection_close_gets_goaway(self):
        sock, r = self.connect()
        sock.sendall(hand_get(1, "/style.css", extra=hand_indexed(0x06, "close")))
        self.assertEqual(r.response()[1], 200)
        ftype, _, _, payload = r.frame()
        self.assertEqual((ftype, payload[:2]), (0x04, b"\x00\x00"))
        self.assertTrue(is_closed(sock))

    def test_one_connection_many_requests(self):
        before = self.server.connections_accepted
        sock, r = self.connect()
        sock.sendall(b"".join(hand_get(i, "/style.css") for i in range(1, 101)))
        self.assertEqual([r.response()[0] for _ in range(100)], list(range(1, 101)))
        self.assertEqual(self.server.connections_accepted - before, 1)

    def test_big_file_split_into_data_frames(self):
        with tempfile.TemporaryDirectory() as root:
            content = os.urandom(100_000)
            with open(os.path.join(root, "blob.bin"), "wb") as f:
                f.write(content)
            server = bserve.BServe(root, "127.0.0.1", 0, log=False)
            server.bind()
            threading.Thread(target=server.serve_forever, daemon=True).start()
            self.addCleanup(server.shutdown)
            sock = socket.create_connection(("127.0.0.1", server.port), timeout=3)
            self.addCleanup(sock.close)
            sock.sendall(b"BHTP/1\r\n" + hand_get(1, "/blob.bin"))
            r = WireReader(sock)
            ftype, flags, _, _ = r.frame()
            sizes, body = [], b""
            while True:
                ftype, flags, _, chunk = r.frame()
                sizes.append(len(chunk))
                body += chunk
                if flags & 1:
                    break
            self.assertEqual(body, content)
            self.assertTrue(all(s <= 16384 for s in sizes))


class IdleTimeoutTest(unittest.TestCase):
    def test_idle_connection_gets_goaway(self):
        server = start_server(idle_timeout=0.3)
        self.addCleanup(server.shutdown)
        sock = socket.create_connection(("127.0.0.1", server.port), timeout=3)
        self.addCleanup(sock.close)
        sock.sendall(b"BHTP/1\r\n")
        ftype, _, _, payload = WireReader(sock).frame()
        self.assertEqual((ftype, payload[:2]), (0x04, b"\x00\x02"))


class CodecTest(unittest.TestCase):
    def test_frame_header_roundtrip(self):
        raw = bp.encode_frame_header(0x123456, 0x02, 0x01, 0xABCDEF)
        self.assertEqual(raw, bytes.fromhex("12345602 01abcdef"))
        self.assertEqual(bp.decode_frame_header(raw), (0x123456, 0x02, 0x01, 0xABCDEF))

    def test_encoder_matches_hand_built_bytes(self):
        self.assertEqual(bp.encode_request(1, "/index.html", "t"), hand_get(1, "/index.html"))

    def test_header_roundtrip_with_literal(self):
        headers = [(":path", "/é"), ("x-custom", "v"), ("server", "")]
        self.assertEqual(bp.decode_headers(bp.encode_headers(headers)), headers)

    def test_decoder_rejects_garbage(self):
        for block in [b"\x01", b"\x01\x00", b"\x01\x00\x05ab", b"\x00", b"\x00\x00",
                      b"\x00\x03ab", b"\x00\x01X\x00\x00", b"\x0b\x00\x00", b"\x02\x00\x02\xff\xfe"]:
            with self.assertRaises(bp.ProtocolError, msg=block):
                bp.decode_headers(block)

    def test_static_table_has_ten_names(self):
        self.assertEqual(len([n for n in bp.STATIC_TABLE if n]), 10)


class BcurlTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = start_server()
        cls.odd_server = start_server(emit_unknown=True)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.odd_server.shutdown()

    def run_bcurl(self, *args):
        with tempfile.TemporaryDirectory() as tmp:
            out = os.path.join(tmp, "out")
            err = io.StringIO()
            with redirect_stderr(err):
                code = bcurl.main(["-o", out] + list(args))
            body = b""
            if os.path.exists(out):
                with open(out, "rb") as f:
                    body = f.read()
        return code, body, err.getvalue()

    def url(self, path, server=None):
        return "localhost:%d%s" % ((server or self.server).port, path)

    def test_success_exit_zero(self):
        code, body, _ = self.run_bcurl(self.url("/style.css"))
        self.assertEqual(code, 0)
        self.assertIn(b"font-family", body)

    def test_4xx_exit_non_zero(self):
        self.assertEqual(self.run_bcurl(self.url("/missing"))[0], 4)

    def test_5xx_exit_five(self):
        with mock.patch.object(bserve, "open", create=True,
                               side_effect=PermissionError(13, "Permission denied")):
            code, body, _ = self.run_bcurl(self.url("/style.css"))
        self.assertEqual(code, 5)
        self.assertIn(b"500 Internal Server Error", body)

    def test_connection_refused_exit_non_zero(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        self.assertEqual(self.run_bcurl("localhost:%d/" % port)[0], 2)

    def test_verbose_hexdumps_every_frame(self):
        code, _, err = self.run_bcurl("-v", self.url("/style.css"))
        self.assertEqual(code, 0)
        for marker in ("> PREFACE", "> REQUEST", "< RESPONSE", "< DATA", "0000  "):
            self.assertIn(marker, err)

    def test_many_paths_one_connection(self):
        before = self.server.connections_accepted
        code, body, err = self.run_bcurl("-v", self.url("/style.css"), "/index.html", "/docs/")
        self.assertEqual(code, 0)
        self.assertEqual(self.server.connections_accepted - before, 1)
        self.assertIn("3 request(s) on 1 connection", err)

    def test_pipeline_and_unknown_frames_from_client(self):
        code, body, _ = self.run_bcurl("--pipeline", "--send-unknown",
                                       self.url("/style.css"), "/style.css")
        self.assertEqual(code, 0)
        self.assertEqual(body.count(b"font-family"), 2)

    def test_client_skips_unknown_frames_from_server(self):
        code, body, _ = self.run_bcurl(self.url("/style.css", self.odd_server))
        self.assertEqual(code, 0)
        self.assertIn(b"font-family", body)

    def test_refuses_second_server(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            bcurl.main([self.url("/a"), "localhost:1/b"])

    def test_parse_target(self):
        self.assertEqual(bcurl.parse_target("localhost:9000/index.html"),
                         ("localhost", 9000, "/index.html"))
        self.assertEqual(bcurl.parse_target("bhtp://h:1"), ("h", 1, "/"))


if __name__ == "__main__":
    unittest.main()
