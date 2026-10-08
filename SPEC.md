# BHTP/1: binary HTTP over one connection

For someone writing a client or server from scratch; every byte of one exchange is in
[HEXDUMP.md](HEXDUMP.md). MUST/SHOULD/MAY as in RFC 2119. Integers: unsigned, big-endian.

## 1. Connection

One TCP connection (bserve listens on 9000). The client MUST first send the 8-byte preface
`42 48 54 50 2F 31 0D 0A` (`BHTP/1\r\n`); a server that receives anything else MUST send
`GOAWAY(PROTOCOL_ERROR)` and close, so a text HTTP client is never misread as frames. After
that both sides send only frames. The connection stays open after each response: a client
MUST NOT open a second connection. It MAY pipeline; the server answers **in request order**.
Either side MAY close; the server SHOULD send `GOAWAY` first.

## 2. Frame header: 8 bytes

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-----------------------------------------------+---------------+
|                  Length (24)                  |   Type (8)    |
+---------------+-------------------------------+---------------+
|   Flags (8)   |               Request ID (24)                 |
+---------------+-----------------------------------------------+
|                  Payload (Length bytes) ...                   |
```

* **Length**: payload bytes after the header. A frame is exactly `8 + Length` bytes, so the
  next frame starts at offset `8 + Length`. No receiver ever scans for a delimiter.
* **Type**: section 4. **Flags**: `0x01` = `END_STREAM`; other bits MUST be ignored, sent as 0.
* **Request ID**: chosen by the client (1, 2, 3, …), echoed on every frame of the answer.
  **ID 0 is the connection's own** and is used by `GOAWAY`. A `REQUEST` on ID 0 is malformed:
  the server answers `400` with Request ID 0 (so the client can still match it) and keeps
  the connection open.

**Why 24/8/8/24 when HTTP/2 uses 24/8/8/31 in 9 bytes?** *Length 24* (16 MiB): 16 bits caps
a header block at 64 KiB, 32 bits wastes a byte per frame; HTTP/2 chose the same. *Type 8*:
256 types, v1 uses 4; version 2 gets room from rule 4.1, not from bits. *Flags 8*: one byte
of booleans, v1 uses one. *Request ID 24*: HTTP/2 needs 31 bits because both peers open
many concurrent, never-reused streams. BHTP has one client, in-order answers and no
multiplexing, so the ID only pairs a response with a pipelined request; 16,777,215 per
connection is plenty. Dropping HTTP/2's reserved bit and 7 ID bits gives **8 bytes, one
64-bit word**. `MAX_PAYLOAD` = 16,384 (HTTP/2's default): no known-type frame may be larger;
a later version can raise it without changing the header.

## 3. Header block

`REQUEST`/`RESPONSE` payloads carry a header block: entries back to back to the end of the
payload (no count). Each starts with a **tag byte**:

| Tag | Entry |
|---|---|
| `0x01`–`0x0A` | Name = static table entry. Then `value-length (16)`, `value`. |
| `0x00` | Literal: `name-length (8, 1–255)`, `name` (lower-case ASCII), `value-length (16)`, `value`. |
| `0x0B`–`0xFF` | Reserved: the block is malformed. |

The static table is the ten names we actually send (01–06 from clients, 07–0A from servers):

```
01 :method      02 :path     03 host           04 user-agent       05 accept
06 connection   07 server    08 content-type   09 content-length   0A last-modified
```

This is HPACK's first two mechanisms (static table, length-prefixed literals) without
Huffman or a dynamic table. A block is **malformed** if an entry runs past the payload, a
tag is reserved, a name is empty or not lower-case ASCII, or a value is not UTF-8.

## 4. Frame types

| Type | Name | From | Payload |
|---|---|---|---|
| `0x01` | `REQUEST` | client | header block; MUST hold `:method` and `:path`, SHOULD hold `host` |
| `0x02` | `RESPONSE` | server | `status (16)`, then header block |
| `0x03` | `DATA` | both | 0 to `MAX_PAYLOAD` body bytes |
| `0x04` | `GOAWAY` | both | `code (16)`, optional UTF-8 reason. Request ID MUST be 0 |

**4.1 Unknown frame types, the rule you may not skip.** A receiver that meets a type it
does not know MUST read and discard exactly `Length` payload bytes and continue with the
next frame, without replying or closing, for any `Length`, even above `MAX_PAYLOAD`. This is
how version 2 adds frame types that a version 1 peer safely ignores.

**END_STREAM** on `REQUEST` or `RESPONSE` means "no body". Otherwise the body follows as
`DATA` frames with the same Request ID, the last flagged `END_STREAM`. `content-length` is
informational; `END_STREAM` is authoritative. `GOAWAY` codes: `0` NO_ERROR, `1`
PROTOCOL_ERROR, `2` IDLE_TIMEOUT; unknown codes are errors. The sender then closes.

## 5. Server behaviour

1. `:method` MUST be `GET`, else **405**.
2. `:path`: drop anything after `?` or `#`, split on `/`, percent-decode each segment. A
   segment that is `.` or `..` or contains `/`, `\` or NUL gives **404**. Join the rest under
   the root; a directory means its `index.html`; missing gives **404**; unreadable gives
   **500**. The server MUST NOT serve anything outside the root.
3. **200**: headers `server`, `content-type`, `content-length`, `last-modified`, then the
   file in `DATA` frames of at most `MAX_PAYLOAD` bytes.
4. **400**, on the offending frame's Request ID, when: the header block is malformed;
   `:method` or `:path` is missing or repeated, or `:path` lacks a leading `/`; the Request
   ID is 0; a known-type frame exceeds `MAX_PAYLOAD` (its bytes are skipped first); `DATA`
   belongs to no open request; the client sends `RESPONSE`. A `REQUEST` arriving before the
   previous one's `END_STREAM` gets the *previous* one a 400 and is itself processed.
   Every frame states its length, so **a bad frame never loses sync: 400, connection stays open**.
5. After a request with `connection: close`: answer, `GOAWAY(NO_ERROR)`, close. Idle longer
   than the server's timeout (bserve: 30 s): `GOAWAY(IDLE_TIMEOUT)`, close. Error responses
   SHOULD carry a short `text/plain` body saying why.

## 6. Client behaviour

Send the preface, then one `REQUEST` per path (IDs 1, 2, 3, …) on the one connection.
Skip unknown types (4.1). Expect `RESPONSE` for the oldest outstanding ID, then `DATA`
until `END_STREAM`. Requests still outstanding at a `GOAWAY` were not answered. `bcurl` writes bodies to stdout; `-v` hexdumps every frame to stderr. Exit status: **0** all
2xx/3xx, **4** any 4xx, **5** any 5xx, **2** connection or protocol failure.
