#!/usr/bin/env python3
"""ftfw — download and decrypt FEETECH servo firmware.

Pulls an image from FEETECH's own update API (the endpoint FD.exe calls), then
decrypts it with the AES-256-ECB key recovered from the GD32 servo bootloader,
and verifies the result is a real Cortex-M firmware image.

The served `.bin` is ciphertext: FD.exe never decrypts it — the servo's
bootloader does. Key location and cipher are documented in
docs/bootloader-analysis.md (§8, §13); the download protocol in docs/download-api.md.

Endpoints (plain HTTP, port 9048, JSON):
    /ftgetzuixinbanben/<appname>   version check
    /ftgetzuixinwenjian/<key>      file fetch   (key = "<main>.<sub>" EEPROM 3.4)

Examples
--------
  # list the known model keys
  ftfw.py list

  # download + decrypt one model in one step (writes .enc.bin and .bin)
  ftfw.py pull 9.3 -o out/

  # use the bundled catalog/ cache instead of the network
  ftfw.py pull 9.3 -o out/ --offline

  # just decrypt a file you already have
  ftfw.py decrypt ST3215/SCServo21-GD32-TTL-250306.bin -o plain.bin

  # discover every model key the server serves (0.0 .. 20.20)
  ftfw.py scan
"""
import argparse, base64, json, os, sys, urllib.request, urllib.error, hashlib, struct

# ── AES-256-ECB key, recovered from bootloader flash @ 0x08007f81 ──────────────
KEY_HEX = "d1841f7c203625582170f38735a876edeeba3a7426e9a02956a248371ac0382b"
# Known-plaintext oracle: E_key(0^16). Every encrypted image has this at offset 0x10.
ORACLE  = bytes.fromhex("9f7f0a29ff25244db8121f9eaf778f47")

HOST    = "http://www.scservo.com:9048"
FETCH   = HOST + "/ftgetzuixinwenjian/%s"
TIMEOUT = 15

# Known model keys -> human label (from README.md catalog; label != flashing guarantee).
CATALOG = {
    "6.16": "SMServo1.0 (485)",  "6.20": "SMServo1.0 (485)",
    "8.0":  "SMServo2.40 (485)",
    "9.2":  "STS family",  "9.3": "STS3215",  "9.4": "STS family",  "9.5": "STS family",
    "9.6":  "STS family",  "9.7": "STS family",  "9.8": "STS family",  "9.9": "STS family",
    "9.10": "STS family",  "9.11": "STS family",  "9.15": "SCServo2.20",
    "10.0": "SMServo3.40 MODBUS",  "10.3": "FT-HTS 3.41",  "10.4": "FT-HTS 3.42",
    "10.6": "STServo3.20",  "10.7": "FT-HTS 3.42",  "10.8": "FT-HLS 3.43",
    "10.9": "STServo3.20",  "10.10": "FT-HLS 3.43",  "10.11": "FT-HLS 3.43",
    "10.12": "FT-HLS 3.43",  "10.13": "FT-HLS 3.43",  "10.14": "FT-HLS 3.43",
    "10.15": "FT-HLS 3.43",  "10.16": "FT-HLS 3.43",  "10.17": "FT-HLS 3.43",
    "10.18": "FT-HLS 3.43",  "10.19": "FT-HLS 3.43",  "10.20": "FT-HLS 3.43",
    "13.1": "LY-TTLSD",
}

# Directory holding cached raw API responses (<key>.json), used for --offline.
CACHE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "catalog")


def _aes_ecb_decrypt(data: bytes) -> bytes:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    key = bytes.fromhex(KEY_HEX)
    n = len(data) // 16 * 16
    d = Cipher(algorithms.AES(key), modes.ECB()).decryptor()
    return d.update(data[:n]) + d.finalize()


def _key_ok() -> bool:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    e = Cipher(algorithms.AES(bytes.fromhex(KEY_HEX)), modes.ECB()).encryptor()
    return e.update(b"\x00" * 16) + e.finalize() == ORACLE


def verify(plain: bytes) -> dict:
    """Sanity-check a decrypted image against the Cortex-M vector table.

    SP must point into SRAM; the reset vector must point into flash with the
    thumb bit set. Flash is at 0x08000000 on GD32/STM32 but 0x00000000 on the
    CW32 parts, so both bases are accepted."""
    sp, rst = struct.unpack_from("<II", plain, 0) if len(plain) >= 8 else (0, 0)
    sp_ok  = 0x20000000 <= sp <= 0x20020000
    thumb  = (rst & 1) == 1
    base_08 = 0x08000000 <= rst <= 0x08080000
    base_00 = 0x00000000 < rst <= 0x00080000
    rst_ok = thumb and (base_08 or base_00)
    app_entry = (rst == 0x080000cd)  # the GD32 bootloader's fixed jump target | thumb
    flash = "0x08000000" if base_08 else ("0x00000000 (CW32)" if base_00 else "?")
    return {"sp": sp, "reset": rst, "sp_ok": sp_ok, "reset_ok": rst_ok,
            "app_entry": app_entry, "flash_base": flash, "valid": sp_ok and rst_ok}


def _http_json(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "ftfw/1.0"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
        return json.loads(r.read().decode("utf-8", "replace"))


def fetch_response(key: str, offline: bool) -> dict:
    """Return the API 'data' object for a model key, from cache or the network."""
    if offline:
        path = os.path.join(CACHE_DIR, key + ".json")
        if not os.path.exists(path):
            sys.exit(f"offline: no cached response for '{key}' at {path}")
        doc = json.load(open(path))
    else:
        try:
            doc = _http_json(FETCH % key)
        except urllib.error.URLError as e:
            sys.exit(f"network error fetching '{key}': {e}. Try --offline to use catalog/.")
    if not doc or doc.get("data") is None:
        msg = (doc or {}).get("message") or "no data"
        sys.exit(f"server has no firmware for key '{key}' ({msg})")
    return doc["data"]


def _ciphertext_from_data(data: dict) -> bytes:
    ct = base64.b64decode(data["wenjian"])
    if len(ct) % 16:
        print(f"  warning: served length {len(ct)} is not a multiple of 16", file=sys.stderr)
    return ct


# ── commands ──────────────────────────────────────────────────────────────────
def cmd_list(_):
    print(f"{'key':<7} {'model (label)':<22} cached")
    print("-" * 40)
    for k in sorted(CATALOG, key=lambda s: tuple(int(x) for x in s.split("."))):
        cached = "yes" if os.path.exists(os.path.join(CACHE_DIR, k + ".json")) else "-"
        print(f"{k:<7} {CATALOG[k]:<22} {cached}")
    print("\nKey = servo EEPROM addr 3 (main) . addr 4 (sub). Read it off the servo "
          "to be sure.\nMany keys share one image (e.g. 9.2-9.11 are byte-identical).")


def _save_pair(outdir, filename, ct, want_enc):
    os.makedirs(outdir, exist_ok=True) if outdir else None
    base = filename if filename.lower().endswith(".bin") else filename + ".bin"
    plain = _aes_ecb_decrypt(ct)
    v = verify(plain)
    out_plain = os.path.join(outdir or ".", base)
    with open(out_plain, "wb") as f:
        f.write(plain)
    written = [out_plain]
    if want_enc:
        out_enc = os.path.join(outdir or ".", base[:-4] + ".enc.bin")
        with open(out_enc, "wb") as f:
            f.write(ct)
        written.append(out_enc)
    return plain, v, written


def cmd_pull(a):
    if not _key_ok():
        sys.exit("internal error: embedded key fails the E(0^16) oracle")
    data = fetch_response(a.key, a.offline)
    ct = _ciphertext_from_data(data)
    fn = data.get("filename") or (a.key + ".bin")
    print(f"key {a.key}: {fn}  banben={data.get('banben')}  "
          f"{len(ct)} bytes ciphertext  sha256={hashlib.sha256(ct).hexdigest()[:16]}…")
    plain, v, written = _save_pair(a.outdir, fn, ct, want_enc=not a.no_enc)
    _report(v, ct)
    for p in written:
        print(f"  wrote {p}")


def cmd_download(a):
    data = fetch_response(a.key, a.offline)
    ct = _ciphertext_from_data(data)
    fn = data.get("filename") or (a.key + ".bin")
    out = os.path.join(a.outdir or ".", fn)
    os.makedirs(a.outdir, exist_ok=True) if a.outdir else None
    with open(out, "wb") as f:
        f.write(ct)
    print(f"wrote {out} ({len(ct)} bytes, still encrypted; run 'ftfw.py decrypt' next)")


def cmd_decrypt(a):
    if not _key_ok():
        sys.exit("internal error: embedded key fails the E(0^16) oracle")
    ct = open(a.infile, "rb").read()
    if ct[16:32] != ORACLE:
        print("  note: block@0x10 != oracle — input may be plaintext already or a "
              "different cipher", file=sys.stderr)
    plain = _aes_ecb_decrypt(ct)
    out = a.outfile or (os.path.splitext(a.infile)[0] + ".plain.bin")
    with open(out, "wb") as f:
        f.write(plain)
    _report(verify(plain), ct)
    print(f"  wrote {out} ({len(plain)} bytes)")


def cmd_scan(a):
    lo, hi = a.range
    print(f"scanning keys {lo}.{lo} .. {hi}.{hi} on {HOST} …")
    hits = 0
    for major in range(lo, hi + 1):
        for minor in range(lo, hi + 1):
            key = f"{major}.{minor}"
            try:
                doc = _http_json(FETCH % key)
            except urllib.error.URLError:
                continue
            d = doc.get("data")
            if d:
                hits += 1
                print(f"  {key:<7} {d.get('banben'):<7} {d.get('filename')}")
    print(f"done: {hits} keys serve firmware")


def _report(v, ct=None):
    if ct is not None:
        ok = ct[16:32] == ORACLE
        print(f"  oracle: block@0x10 {'==' if ok else '!='} E(0^16) -> key "
              f"{'CONFIRMED' if ok else 'MISMATCH (wrong key or cipher)'}")
    tag = "VALID Cortex-M image" if v["valid"] else "unrecognized vector layout (?)"
    extra = ""
    if v["app_entry"]:
        extra = "  [reset == GD32 bootloader app-entry 0x080000cc]"
    elif v["valid"]:
        extra = f"  [flash base {v['flash_base']}]"
    print(f"  verify: SP=0x{v['sp']:08x} reset=0x{v['reset']:08x} -> {tag}{extra}")


def main():
    ap = argparse.ArgumentParser(prog="ftfw.py", description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("list", help="show known model keys")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("pull", help="download + decrypt + verify")
    p.add_argument("key", help="model key, e.g. 9.3")
    p.add_argument("-o", "--outdir", default="out", help="output directory (default: out)")
    p.add_argument("--offline", action="store_true", help="use catalog/ cache, no network")
    p.add_argument("--no-enc", action="store_true", help="don't also save the .enc.bin ciphertext")
    p.set_defaults(func=cmd_pull)

    p = sub.add_parser("download", help="download ciphertext only")
    p.add_argument("key")
    p.add_argument("-o", "--outdir", default="out")
    p.add_argument("--offline", action="store_true")
    p.set_defaults(func=cmd_download)

    p = sub.add_parser("decrypt", help="decrypt a local ciphertext .bin")
    p.add_argument("infile")
    p.add_argument("-o", "--outfile")
    p.set_defaults(func=cmd_decrypt)

    p = sub.add_parser("scan", help="enumerate model keys on the server")
    p.add_argument("--range", nargs=2, type=int, default=[0, 20], metavar=("LO", "HI"))
    p.set_defaults(func=cmd_scan)

    a = ap.parse_args()
    a.func(a)


if __name__ == "__main__":
    main()
