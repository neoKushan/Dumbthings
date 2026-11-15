#!/usr/bin/env python3
"""Decode otm_plaintext_capture.log: hex blocks (TX/RX) -> CoAP (RFC7252/RFC8323) -> CBOR.
Usage: python decode_capture.py [logfile]
"""
import sys, re

LOG = sys.argv[1] if len(sys.argv) > 1 else "otm_plaintext_capture.log"

# ---- minimal CBOR decoder (enough for OCF reps) ----
def cbor(b, i=0):
    if i >= len(b): return ("<eof>", i)
    ib = b[i]; mt = ib >> 5; ai = ib & 0x1f; i += 1
    def length(ai, i):
        if ai < 24: return ai, i
        if ai == 24: return b[i], i + 1
        if ai == 25: return int.from_bytes(b[i:i+2], 'big'), i + 2
        if ai == 26: return int.from_bytes(b[i:i+4], 'big'), i + 4
        if ai == 27: return int.from_bytes(b[i:i+8], 'big'), i + 8
        return None, i  # indefinite
    if mt == 0: v, i = length(ai, i); return v, i
    if mt == 1: v, i = length(ai, i); return -1 - v, i
    if mt in (2, 3):
        if ai == 31:  # indefinite string
            parts = []
            while b[i] != 0xff:
                s, i = cbor(b, i); parts.append(s)
            i += 1
            return ("".join(map(str, parts)) if mt == 3 else b"".join(parts)), i
        n, i = length(ai, i); chunk = b[i:i+n]; i += n
        return (chunk.decode('utf-8', 'replace') if mt == 3 else chunk.hex()), i
    if mt == 4:
        arr = []
        if ai == 31:
            while b[i] != 0xff: v, i = cbor(b, i); arr.append(v)
            i += 1
        else:
            n, i = length(ai, i)
            for _ in range(n): v, i = cbor(b, i); arr.append(v)
        return arr, i
    if mt == 5:
        d = {}
        if ai == 31:
            while b[i] != 0xff:
                k, i = cbor(b, i); v, i = cbor(b, i); d[k] = v
            i += 1
        else:
            n, i = length(ai, i)
            for _ in range(n):
                k, i = cbor(b, i); v, i = cbor(b, i); d[k] = v
        return d, i
    if mt == 7:
        if ai == 20: return False, i
        if ai == 21: return True, i
        if ai == 22: return None, i
        v, i = length(ai, i); return ("simple(%s)" % v), i
    return ("<mt%d>" % mt), i

# ---- CoAP ----
CODES = {1: "GET", 2: "POST", 3: "PUT", 4: "DELETE"}
def rsp(code): return "%d.%02d" % (code >> 5, code & 0x1f)

def parse_options(b, i, path_only=False):
    opts = {}; num = 0; path = []
    while i < len(b) and b[i] != 0xff:
        d = b[i] >> 4; l = b[i] & 0xf; i += 1
        if d == 13: d = b[i] + 13; i += 1
        elif d == 14: d = int.from_bytes(b[i:i+2], 'big') + 269; i += 2
        if l == 13: l = b[i] + 13; i += 1
        elif l == 14: l = int.from_bytes(b[i:i+2], 'big') + 269; i += 2
        num += d; val = b[i:i+l]; i += l
        if num == 11: path.append(val.decode('utf-8', 'replace'))
        else: opts.setdefault(num, []).append(val.hex())
    if i < len(b) and b[i] == 0xff: i += 1
    return opts, "/".join(path), i

def decode_coap(b):
    if len(b) < 1: return None
    # try RFC7252 (UDP): ver=1
    try:
        if (b[0] >> 6) == 1:
            tkl = b[0] & 0xf; code = b[1]; mid = int.from_bytes(b[2:4], 'big')
            i = 4 + tkl
            opts, path, i = parse_options(b, i)
            payload = b[i:]
            return ("7252", code, path, opts, payload)
    except Exception:
        pass
    # try RFC8323 (TCP/BLE): len(4)|tkl(4)
    try:
        ln = b[0] >> 4; tkl = b[0] & 0xf; i = 1; extlen = 0
        if ln == 13: extlen = b[i]; i += 1
        elif ln == 14: extlen = int.from_bytes(b[i:i+2], 'big'); i += 2
        elif ln == 15: extlen = int.from_bytes(b[i:i+4], 'big'); i += 4
        code = b[i]; i += 1; i += tkl
        opts, path, i = parse_options(b, i)
        payload = b[i:]
        return ("8323", code, path, opts, payload)
    except Exception:
        return None

def fmt_code(code):
    return CODES.get(code, rsp(code))

def main():
    txt = open(LOG, encoding="utf-8", errors="replace").read()
    blocks = re.split(r"===== \[(TX|RX)\] ([0-9:.]+)\s+len=(\d+) =====", txt)
    # blocks: [pre, tag, ts, len, body, tag, ts, len, body, ...]
    for k in range(1, len(blocks), 4):
        tag, ts, length, body = blocks[k], blocks[k+1], blocks[k+2], blocks[k+3]
        hexbytes = "".join(re.findall(r"^[0-9a-f]{4}\s+((?:[0-9a-f]{2} )+)", body, re.M))
        data = bytes.fromhex(hexbytes.replace(" ", ""))
        if not data: continue
        dec = decode_coap(data)
        print(f"\n### [{tag}] {ts} len={length}")
        if not dec:
            print("  (coap parse failed) first64:", data[:64].hex()); continue
        fr, code, path, opts, payload = dec
        line = f"  {fr} {fmt_code(code)} /{path}"
        if opts: line += f"  opts={opts}"
        print(line)
        if payload:
            try:
                obj, _ = cbor(payload)
                print("  cbor:", obj)
            except Exception as e:
                print("  payload(hex):", payload[:80].hex(), f"(cbor err {e})")

if __name__ == "__main__":
    main()
