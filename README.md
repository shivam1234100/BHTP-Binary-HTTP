# BHTP/1: HTTP, in binary

A binary HTTP with its own spec, a server (`bserve`) and a client (`bcurl`), on raw TCP
sockets. **Python 3.8+, standard library only, nothing to install.** On Windows use `py`
where this says `python3`.

## Run it

```bash
chmod +x bserve bcurl                         # macOS/Linux, once
./bserve ./www 9000                           # terminal 1
./bcurl -v localhost:9000/index.html          # terminal 2: body on stdout, frames on stderr
./bcurl localhost:9000/index.html /missing.html; echo $?    # one connection; exits 4
```

Windows: `.\bserve www 9000` and `.\bcurl -v localhost:9000/index.html`.

## Tests

```bash
python3 -m unittest discover -s tests -v      # 37 tests, OK
```

## Hand-in

| Hand-in | File |
|---|---|
| 1. The spec (two pages) | [SPEC.md](SPEC.md) |
| 2. The program | `bserve.py`, `bcurl.py`, shared codec `bproto.py` (plus `bserve`/`bcurl` launchers and `.cmd` for Windows) |
| 3. Annotated hexdump | [HEXDUMP.md](HEXDUMP.md), from the raw capture in `captures/` |

**Server** (`./bserve ./www 9000`): accepts a TCP connection, reads binary request frames,
maps the path to a file under the root, replies with status, headers and the bytes; 404 if
it is not there, 400 if the frame is malformed, and keeps the connection open.

**Client** (`./bcurl -v localhost:9000/index.html`): builds the binary request frame, writes
the response body to stdout, `-v` hexdumps every frame, exits non-zero on 4xx / 5xx, and
never opens a second connection.

`bcurl --pipeline --send-unknown …` and `bserve --emit-unknown` inject unknown frame types
to show both sides skip them (SPEC §4.1). `RawWireTest` in `tests/` builds every frame by
hand from SPEC.md, so the server is tested against the document, not against our client.
