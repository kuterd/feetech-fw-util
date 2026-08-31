# feetech-servo-fw

Tools and protocol notes for FEETECH serial-bus servos (STS/SCS/ST family and
relatives): **download firmware from the vendor server, decrypt it, and
understand how the servo bootloader flashes it.**

The vendor's own images are AES-256-ECB ciphertext and the updater (`FD.exe`)
never decrypts them — the servo's bootloader does. The key was recovered from a
GD32 bootloader flash dump, so the images can now be decrypted, inspected, and
disassembled offline.

> **Reverse-engineering / interoperability project.** Not affiliated with or
> endorsed by FEETECH. Firmware images are FEETECH's; none are redistributed here
> — the tools fetch them from the vendor server on demand. See
> [Legal](#legal-and-safety).

## What's here

| Path | What it is |
|---|---|
| [`ftfw.py`](ftfw.py) | Download + decrypt + verify, by model key. The main tool. |
| [`decrypt.py`](decrypt.py) | Lower-level multi-cipher decrypt/verify + bootloader-dump key miner. |
| [`docs/download-api.md`](docs/download-api.md) | The vendor update HTTP API and the model-key catalog. |
| [`docs/firmware-update-protocol.md`](docs/firmware-update-protocol.md) | **Host side** of the flash protocol, from the `FD.exe` disassembly. |
| [`docs/bootloader-analysis.md`](docs/bootloader-analysis.md) | **Device side**: the GD32 bootloader receiver, the CRC, the AES key, verification. |

## Quickstart

```bash
pip install cryptography          # only dependency

python3 ftfw.py list              # known model keys
python3 ftfw.py pull 9.3 -o out/  # download + decrypt + verify -> out/*.bin
```

`pull` writes the decrypted image and, by default, the original ciphertext
(`.enc.bin`) next to it; add `--no-enc` to skip the latter. Each decrypt is
checked two ways — the `E(0^16)` oracle confirms the key, and the Cortex-M
vector table confirms the plaintext:

```
key 9.3: SCServo21-GD32-TTL-250306.bin  banben=3.10  16816 bytes ciphertext ...
  oracle: block@0x10 == E(0^16) -> key CONFIRMED
  verify: SP=0x20001000 reset=0x080000cd -> VALID Cortex-M image  [reset == GD32 bootloader app-entry 0x080000cc]
```

The **model key is the servo's EEPROM address 3 . address 4** — read it off the
real servo before flashing (see [`docs/download-api.md`](docs/download-api.md)).
Many keys share one image (e.g. 9.2–9.11 are byte-identical).

Other commands:

```bash
python3 ftfw.py download 9.3 -o out/    # ciphertext only
python3 ftfw.py decrypt FILE -o OUT     # decrypt a .bin you already have
python3 ftfw.py pull 9.3 --offline      # use a local catalog/ cache instead of the network
python3 ftfw.py scan                    # enumerate every key the server serves
```

`--offline` reads cached API responses from a `catalog/<key>.json` directory next
to the script; none ship with the repo (no vendor firmware is redistributed), so
populate it yourself from `download`/`scan` output if you want offline use.

## How it fits together

```
  vendor server  ──HTTP──►  base64 wenjian  ──►  AES-256-ECB ciphertext .bin
  (download-api)                                        │
                                              ftfw.py / decrypt.py
                                              AES-256-ECB, key @ bootloader 0x08007f81
                                                        ▼
                                              plaintext Cortex-M image
                                                        │
                          the servo does the same decrypt in its bootloader
                          while receiving 70-byte blocks over the wire
                          (firmware-update-protocol + bootloader-analysis)
```

- **Download** — the vendor API and model-key scheme: `docs/download-api.md`.
- **Encryption** — AES-256-ECB, one product-wide key at flash `0x08007f81`;
  recovery and end-to-end verification in `docs/bootloader-analysis.md` §8/§13.
- **Flashing** — the wire protocol the bootloader speaks: magic preamble, the
  70-byte block frame, the XMODEM-family CRC (over an unusual region), ACK/NAK,
  and the reset-vector patch. Host side in `docs/firmware-update-protocol.md`,
  device side in `docs/bootloader-analysis.md`.

The same AES-256 key decrypts the entire product line tested (GD32, STM32, and
CW32 parts alike).

## The key

Recovered from GD32 bootloader flash at `0x08007f81`, immediately after the
`"1fBVA"` magic string:

```
d1841f7c203625582170f38735a876edeeba3a7426e9a02956a248371ac0382b
```

AES-256, ECB mode (no IV). Confirmed by `E_key(0^16) =
9f7f0a29ff25244db8121f9eaf778f47`, the block present at offset `0x10` of every
vendor image, and by decrypting a real image to a valid Cortex-M vector table
whose reset vector lands on the bootloader's own hardcoded application entry.
Full derivation: `docs/bootloader-analysis.md`.

## Legal and safety

- **Nothing here has been tested against hardware.** The protocol was read out of
  disassembly. Flashing a servo with a mis-identified or malformed image can brick
  it; a failed transfer leaves the device in its bootloader. Read the servo's
  EEPROM version bytes and understand `docs/bootloader-analysis.md` §7 before you
  write anything to a servo.
- **No firmware is redistributed.** The tools download FEETECH's images from
  FEETECH's server at your request; those images are FEETECH's copyright. This
  repo contains only original tooling and protocol notes, produced for
  interoperability and study. Not affiliated with FEETECH.
- The tooling in this repo (`ftfw.py`, `decrypt.py`) is under the MIT license; see
  [`LICENSE`](LICENSE). The prose in `docs/` describes an independently
  reverse-engineered protocol.
