# Annotated hexdump: one complete request and response

Every byte below comes from a real run, not typed by hand:

```
./bserve ./www 9000                                   # terminal 1
./bcurl -v localhost:9000/index.html > /dev/null      # terminal 2
```

The unedited `-v` output is [captures/index-html-exchange.txt](captures/index-html-exchange.txt).
Offsets are from the start of each frame. Section numbers refer to [SPEC.md](SPEC.md).

| Direction | Frames | Bytes on the wire |
|---|---|---|
| client → server | preface (8) + `REQUEST` (8 + 55) | **71** |
| server → client | `RESPONSE` (8 + 80) + `DATA` (8 + 152) | **248** |

For comparison, the same request as HTTP/1.1 text is 86 bytes, and the receiver has to scan
it for CRLFs to find where it ends. Here every frame says its own length in its first 3 bytes.

## 1. Client → server: preface (8 bytes)

```
0000  42 48 54 50 2f 31 0d 0a                           |BHTP/1..|
```

`BHTP/1\r\n` in ASCII (SPEC 1). Sent once per connection, before any frame.

## 2. Client → server: REQUEST frame (8 + 55 = 63 bytes)

```
0000  00 00 37 01 01 00 00 01  01 00 03 47 45 54 02 00  |..7........GET..|
0010  0b 2f 69 6e 64 65 78 2e  68 74 6d 6c 03 00 0e 6c  |./index.html...l|
0020  6f 63 61 6c 68 6f 73 74  3a 39 30 30 30 04 00 09  |ocalhost:9000...|
0030  62 63 75 72 6c 2f 31 2e  30 05 00 03 2a 2f 2a     |bcurl/1.0...*/*|
```

| Offset | Bytes | Field | Meaning |
|---|---|---|---|
| 0x00 | `00 00 37` | Length (24) | 0x37 = **55** payload bytes follow the header |
| 0x03 | `01` | Type (8) | `REQUEST` |
| 0x04 | `01` | Flags (8) | `END_STREAM`: no body follows |
| 0x05 | `00 00 01` | Request ID (24) | request **1** |
| 0x08 | `01` | tag | static index 1 = `:method` |
| 0x09 | `00 03` | value length | 3 |
| 0x0B | `47 45 54` | value | `GET` |
| 0x0E | `02` | tag | static index 2 = `:path` |
| 0x0F | `00 0b` | value length | 11 |
| 0x11 | `2f 69 6e 64 65 78 2e 68 74 6d 6c` | value | `/index.html` |
| 0x1C | `03` | tag | static index 3 = `host` |
| 0x1D | `00 0e` | value length | 14 |
| 0x1F | `6c 6f 63 61 6c 68 6f 73 74 3a 39 30 30 30` | value | `localhost:9000` |
| 0x2D | `04` | tag | static index 4 = `user-agent` |
| 0x2E | `00 09` | value length | 9 |
| 0x30 | `62 63 75 72 6c 2f 31 2e 30` | value | `bcurl/1.0` |
| 0x39 | `05` | tag | static index 5 = `accept` |
| 0x3A | `00 03` | value length | 3 |
| 0x3C | `2a 2f 2a` | value | `*/*` |
| 0x3F | | end | 8 + 55 = 63. The next byte would start the next frame. |

Check: (1+2+3) + (1+2+11) + (1+2+14) + (1+2+9) + (1+2+3) = 6 + 14 + 17 + 12 + 6 = **55**.

## 3. Server → client: RESPONSE frame (8 + 80 = 88 bytes)

```
0000  00 00 50 02 00 00 00 01  00 c8 07 00 0a 62 73 65  |..P..........bse|
0010  72 76 65 2f 31 2e 30 08  00 18 74 65 78 74 2f 68  |rve/1.0...text/h|
0020  74 6d 6c 3b 20 63 68 61  72 73 65 74 3d 75 74 66  |tml; charset=utf|
0030  2d 38 09 00 03 31 35 32  0a 00 1d 46 72 69 2c 20  |-8...152...Fri, |
0040  32 35 20 53 65 70 20 32  30 32 36 20 31 30 3a 31  |25 Sep 2026 10:1|
0050  32 3a 32 33 20 47 4d 54                           |2:23 GMT|
```

| Offset | Bytes | Field | Meaning |
|---|---|---|---|
| 0x00 | `00 00 50` | Length | 0x50 = **80** payload bytes |
| 0x03 | `02` | Type | `RESPONSE` |
| 0x04 | `00` | Flags | no `END_STREAM`: a body follows in `DATA` frames |
| 0x05 | `00 00 01` | Request ID | answers request **1** |
| 0x08 | `00 c8` | status (16) | 0x00C8 = **200** |
| 0x0A | `07` | tag | static index 7 = `server` |
| 0x0B | `00 0a` | value length | 10 |
| 0x0D | `62 73 65 72 76 65 2f 31 2e 30` | value | `bserve/1.0` |
| 0x17 | `08` | tag | static index 8 = `content-type` |
| 0x18 | `00 18` | value length | 24 |
| 0x1A | `74 65 78 74 … 75 74 66 2d 38` (24 bytes) | value | `text/html; charset=utf-8` |
| 0x32 | `09` | tag | static index 9 = `content-length` |
| 0x33 | `00 03` | value length | 3 |
| 0x35 | `31 35 32` | value | `152` (informational; `END_STREAM` decides, SPEC 4) |
| 0x38 | `0a` | tag | static index 10 = `last-modified` |
| 0x39 | `00 1d` | value length | 29 |
| 0x3B | `46 72 69 2c … 47 4d 54` (29 bytes) | value | `Fri, 25 Sep 2026 10:12:23 GMT` |
| 0x58 | | end | 8 + 80 = 88 |

Check: 2 + (1+2+10) + (1+2+24) + (1+2+3) + (1+2+29) = 2 + 13 + 27 + 6 + 32 = **80**.

## 4. Server → client: DATA frame (8 + 152 = 160 bytes)

```
0000  00 00 98 03 01 00 00 01  3c 21 64 6f 63 74 79 70  |........<!doctyp|
0010  65 20 68 74 6d 6c 3e 0a  3c 68 74 6d 6c 3e 3c 68  |e html>.<html><h|
0020  65 61 64 3e 3c 6d 65 74  61 20 63 68 61 72 73 65  |ead><meta charse|
0030  74 3d 22 75 74 66 2d 38  22 3e 3c 74 69 74 6c 65  |t="utf-8"><title|
0040  3e 62 73 65 72 76 65 3c  2f 74 69 74 6c 65 3e 3c  |>bserve</title><|
0050  2f 68 65 61 64 3e 0a 3c  62 6f 64 79 3e 3c 68 31  |/head>.<body><h1|
0060  3e 48 65 6c 6c 6f 20 66  72 6f 6d 20 62 73 65 72  |>Hello from bser|
0070  76 65 3c 2f 68 31 3e 3c  70 3e 53 65 72 76 65 64  |ve</h1><p>Served|
0080  20 6f 76 65 72 20 42 48  54 50 2f 31 2e 3c 2f 70  | over BHTP/1.</p|
0090  3e 3c 2f 62 6f 64 79 3e  3c 2f 68 74 6d 6c 3e 0a  |></body></html>.|
```

| Offset | Bytes | Field | Meaning |
|---|---|---|---|
| 0x00 | `00 00 98` | Length | 0x98 = **152** bytes: the whole file fits in one frame (≤ 16,384) |
| 0x03 | `03` | Type | `DATA` |
| 0x04 | `01` | Flags | `END_STREAM`: last frame of response 1 |
| 0x05 | `00 00 01` | Request ID | belongs to request **1** |
| 0x08–0x17 | `3c 21 … 3e 0a` (16) | body line 1 | `<!doctype html>` + LF |
| 0x18–0x56 | `3c 68 … 3e 0a` (63) | body line 2 | `<html><head><meta charset="utf-8"><title>bserve</title></head>` + LF |
| 0x57–0x9F | `3c 62 … 3e 0a` (73) | body line 3 | `<body><h1>Hello from bserve</h1><p>Served over BHTP/1.</p></body></html>` + LF |
| 0xA0 | | end | 8 + 152 = 160 |

The payload is `www/index.html` byte for byte (16 + 63 + 73 = **152**), and it is what
`bcurl` writes to stdout. The connection is still open after this frame; `bcurl` then
closes it because it has nothing more to ask, and the server logs
`conn #1 closed after 1 request(s): client closed`.

## 5. Skipping an unknown frame (SPEC 4.1)

`./bcurl -v localhost:9001/style.css` against `./bserve ./www 9001 --emit-unknown`, which
puts a frame of type `0x7e` between the `RESPONSE` and the `DATA`:

```
< UNKNOWN(0x7e) len=32 flags=0x00(-) id=1
<   0000  00 00 20 7e 00 00 00 01                           |.. ~....|
<   (unknown type or oversize: skipped, still in sync)
< DATA len=34 flags=0x01(END_STREAM) id=1
```

`bcurl` read the 8-byte header, saw a type it does not know, discarded Length = 0x20 = 32
payload bytes, and the very next byte was the header of the `DATA` frame.
