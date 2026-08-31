#!/usr/bin/env python3
"""Decrypt / verify FEETECH servo firmware images (low-level, multi-cipher).

The key is known: it was recovered from the GD32 servo bootloader flash at
0x08007f81 (see docs/bootloader-analysis.md). The cipher is AES-256-ECB with a
single product-wide key:

    aes-256  d1841f7c203625582170f38735a876edeeba3a7426e9a02956a248371ac0382b

For the everyday "download + decrypt" workflow use ftfw.py, which has this key
built in. This tool is the lower-level bench: it takes an arbitrary cipher+key,
auto-verifies against the known-plaintext oracle, and can mine a raw bootloader
flash dump for the key of another product line.

Global known-plaintext oracle (holds for every image, every MCU family):
    E(0x00 * 16) == 9f7f0a29ff25244db8121f9eaf778f47
so any candidate key is confirmed/rejected instantly, before decrypting.

Usage
-----
  # 1. Decrypt an image with the known key:
  python3 decrypt.py --cipher aes-256 \
      --key d1841f7c203625582170f38735a876edeeba3a7426e9a02956a248371ac0382b \
      --in firmware.enc.bin --out firmware.bin

  # 2. You have a raw bootloader flash dump and want the key found for you:
  python3 decrypt.py --scan-dump bootloader_dump.bin
      # brute-forces every 16/24/32-byte window in the dump as a key, across
      # AES/SM4/Camellia/SEED, against the oracle; prints any that matches.

  # 3. Just inspect an image / confirm it is still encrypted:
  python3 decrypt.py --inspect firmware.enc.bin
"""
import argparse, sys, glob, os, warnings
warnings.filterwarnings("ignore")
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

ORACLE_PT  = b"\x00" * 16
ORACLE_CT  = bytes.fromhex("9f7f0a29ff25244db8121f9eaf778f47")

CIPHERS = {   # name -> (algorithm, allowed key lengths in bytes)
    "aes-128": (algorithms.AES, (16,)),  "aes-192": (algorithms.AES, (24,)),
    "aes-256": (algorithms.AES, (32,)),  "sm4":     (algorithms.SM4, (16,)),
    "camellia-128": (algorithms.Camellia, (16,)),
    "camellia-256": (algorithms.Camellia, (32,)),
    "seed": (algorithms.SEED, (16,)),
}

def _cipher(algo, key):
    return Cipher(algo(key), modes.ECB())

def encrypt_block(algo, key, pt):
    try:
        e = _cipher(algo, key).encryptor(); return e.update(pt) + e.finalize()
    except Exception:
        return None

def key_matches_oracle(algo, key):
    return encrypt_block(algo, key, ORACLE_PT) == ORACLE_CT

def ecb_decrypt(algo, key, data):
    d = _cipher(algo, key).decryptor()
    return d.update(data) + d.finalize()

def looks_like_cortex_m3(plain):
    """A decrypted image should begin with a Cortex-M vector table:
    word0 = initial SP in SRAM (0x2000_0000..0x2001_ffff for a GD32F103),
    word1 = reset handler in flash (0x0800_0000..0x0808_0000), thumb bit set."""
    if len(plain) < 8:
        return False
    sp  = int.from_bytes(plain[0:4], "little")
    rst = int.from_bytes(plain[4:8], "little")
    sp_ok  = 0x20000000 <= sp  <= 0x20020000
    rst_ok = 0x08000000 <= rst <= 0x08080000 and (rst & 1) == 1
    return sp_ok and rst_ok

def cmd_inspect(path):
    b = open(path, "rb").read()
    import collections, math
    c = collections.Counter(b)
    H = -sum(v/len(b)*math.log2(v/len(b)) for v in c.values())
    blk1 = b[16:32]
    print(f"{os.path.basename(path)}: {len(b)} bytes, entropy {H:.3f} b/byte, len%16={len(b)%16}")
    print(f"  block@0x10 = {blk1.hex()}")
    if blk1 == ORACLE_CT:
        print("  -> matches E(0^16) oracle: standard encrypted image, key not yet known.")
    print(f"  vector-table check on raw bytes: {'plausible (already plaintext?)' if looks_like_cortex_m3(b) else 'no -> still encrypted'}")

def cmd_decrypt(args):
    if args.cipher not in CIPHERS:
        sys.exit(f"unknown cipher {args.cipher}; choose from {', '.join(CIPHERS)}")
    algo, sizes = CIPHERS[args.cipher]
    key = bytes.fromhex(args.key)
    if len(key) not in sizes:
        sys.exit(f"{args.cipher} needs a {sizes} byte key; got {len(key)}")
    if not key_matches_oracle(algo, key):
        print("!! key/cipher does NOT satisfy E(0^16)=9f7f...; it is almost certainly wrong.")
        if not args.force:
            sys.exit("   refusing to write a bogus decryption (use --force to override).")
    else:
        print("** key verified against the E(0^16) oracle **")
    data = open(args.infile, "rb").read()
    if len(data) % 16:
        data = data[:len(data)//16*16]
    plain = ecb_decrypt(algo, key, data)
    open(args.outfile, "wb").write(plain)
    ok = looks_like_cortex_m3(plain)
    sp  = int.from_bytes(plain[0:4], "little"); rst = int.from_bytes(plain[4:8], "little")
    print(f"wrote {args.outfile} ({len(plain)} bytes)")
    print(f"  vector table: SP=0x{sp:08x} reset=0x{rst:08x} -> {'VALID Cortex-M3 image' if ok else 'does not look like M3 firmware (key likely wrong)'}")

def cmd_scan_dump(path):
    """Slide a window over a bootloader dump; test each as a key vs the oracle."""
    dump = open(path, "rb").read()
    print(f"scanning {len(dump)} bytes for a key satisfying E(0^16)=9f7f... across {len(CIPHERS)} ciphers")
    hits = 0
    for off in range(0, len(dump) - 16):
        for name, (algo, sizes) in CIPHERS.items():
            for L in sizes:
                if off + L > len(dump):
                    continue
                if key_matches_oracle(algo, dump[off:off+L]):
                    print(f"  *** MATCH {name} key @dump+0x{off:x}: {dump[off:off+L].hex()} ***")
                    hits += 1
    if not hits:
        print("  no standard-cipher key found in the dump. If the bootloader uses a")
        print("  custom cipher, reverse the decrypt routine instead (the key may be")
        print("  split, derived, or the algorithm non-standard).")

def main():
    ap = argparse.ArgumentParser(description="Decrypt/verify FEETECH firmware images")
    ap.add_argument("--cipher"); ap.add_argument("--key")
    ap.add_argument("--in", dest="infile"); ap.add_argument("--out", dest="outfile")
    ap.add_argument("--inspect"); ap.add_argument("--scan-dump", dest="scandump")
    ap.add_argument("--force", action="store_true")
    a = ap.parse_args()
    if a.inspect:
        cmd_inspect(a.inspect)
    elif a.scandump:
        cmd_scan_dump(a.scandump)
    elif a.cipher and a.key and a.infile and a.outfile:
        cmd_decrypt(a)
    else:
        ap.print_help()
        print("\nTip: the known key is AES-256")
        print("  d1841f7c203625582170f38735a876edeeba3a7426e9a02956a248371ac0382b")
        print("or just use ftfw.py to download and decrypt in one step.")

if __name__ == "__main__":
    main()
