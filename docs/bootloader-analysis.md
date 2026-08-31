# FEETECH GD32 servo bootloader — device side of the firmware update protocol

Companion to [`firmware-update-protocol.md`](firmware-update-protocol.md), which describes the
**host** side reversed from `FD.exe`. This document describes the **device** side, reversed
from the GD32 servo firmware disassembly in `functions/asm/` (ARM Thumb-2, one file per
function, radare2 naming `fcn.<addr>.asm`).

Everything below was read out of the disassembly. Nothing has been tested against hardware.

The whole receiver is a single function: **`fcn.08007cfc`** (530 bytes at `0x08007cfc`).

---

## 1. Function map

| Address | Role |
|---|---|
| `0x08007800` | Bootloader entry (`aav.0x08007801`, thumb) — calls clock init then the receive loop |
| `0x0800789c` | Clock/PLL init, called from the entry stub at `+0x29` |
| `0x08007cfc` | **The protocol** — UART/timer init, preamble match, block loop, CRC, flash write, verify |
| `0x08007f44` | Send one byte on USART1 (half-duplex: disable RX, enable TX, wait TC, restore) |
| `0x08007ce8` | Leave the bootloader — jump to the application at `0x080000cc` if it is not erased |
| `0x0800784c` | Flash page erase (`FMC` at `0x40022000`) |
| `0x08007878` | Flash program halfword |
| `0x08007c2c` | AES key expansion + IV setup |
| `0x08007c98` | AES-CBC decrypt of a buffer (`r0` = pointer, `r1` = length) |
| `0x08007bdc` | AES block decrypt (equivalent inverse cipher, 14 rounds) |
| `0x08007b0c` | Key schedule from the 32-byte key at `0x08007f81` |
| `0x08007900` / `0x08007934` | S-box / inverse S-box generation (log-exp tables, `0x1b`, `0x63`) |
| `0x08007ad6` / `0x08007af4` | XOR-into and copy byte helpers |
| `0x08002590` | Application-side SCS instruction dispatcher (handles instruction `0x08`) |

Memory:

| Address | Contents |
|---|---|
| `0x08000000` | Application vector table. `0x08000004` (reset vector) is force-written to `0x08007801` |
| `0x080000cc` | Fixed application entry point — where `fcn.08007ce8` jumps |
| `0x080073ff` | Last byte of the application region (~29.5 KiB, 464 blocks max) |
| `0x08007800` | Bootloader (not writable by the protocol; the loop stops before it) |
| `0x08007f7c` | ASCII `"1fBVA"` — the expected magic preamble |
| `0x08007f81` | **32-byte AES key** (immediately after the preamble string) |
| `0x20000320` | 70-byte receive frame buffer |
| `0x20000323` | = frame + 3, the 64-byte payload field |

Peripherals: USART1 `0x40004400`, TIMER13 `0x40002000`, RCU `0x40021000`, GPIO `0x48000000`,
FMC `0x40022000`.

---

## 2. Reset always lands in the bootloader

`fcn.08000000.asm:13` — the application vector table's reset vector reads `0x08007801`, and
the block loop rewrites those two halfwords on every update (§6). So every reset enters the
bootloader; the application is reached only through `fcn.08007ce8`, which reads the word at
`0x080000cc` and calls it unless it is `0xFFFFFFFF` (erased):

```c
void leave_bootloader(void) {
    if (*(uint32_t *)0x080000cc != 0xFFFFFFFF)
        ((void(*)(void))0x080000cc)();
}
```

This is why the protocol doc's §7 "the servo is left in the bootloader" is survivable: a
failed update leaves the reset vector pointing here, so re-running the update works.

---

## 3. Setup (`0x08007cfc`–`0x08007d60`)

- USART1 clocked and configured: `CTL0 = 0`, `BAUD = 0x60`, `CTL2 = 8`, `CTL0 = 5` (UEN|REN).
  48 MHz / 96 = **500000 baud**, 8N1 — matching the host's post-wake-up rate.
- GPIO port A pin config for the USART pins.
- TIMER13: `PSC = 0xBB7F` (47999) → 1 kHz, `CAR = 0x320` (800) → **800 ms**, `SWEVG = 1`,
  `INTF = 0`, `CTL0 = 1`.

The timer is only polled in the two waiting loops of §4. Once a block starts arriving there
is **no timeout at all** — the receive loop spins on RBNE until all 70 bytes arrive.

---

## 4. Handshake

### Preamble (`0x08007d62`–`0x08007d8c`)

```c
i = 0;
while (i < 5) {
    if (timer_expired()) { clear_timer(); leave_bootloader(); }
    if (!(USART1->STAT & RBNE)) continue;
    i = (USART1->RDATA == "1fBVA"[i]) ? i + 1 : 0;   /* mismatch restarts at 0 */
}
send(0x06);
```

The string compared against is `"1fBVA"` at `0x08007f7c` — i.e. this firmware implements the
**bus-servo (`.bin` / `.hex`) path** of the host protocol, not the `.xbin` `"ABV1f"` variant.

Note the device does reply to the preamble with `0x06`. The host reads that byte and only
checks it for timeout (protocol doc §9, open question 2) — it is a plain ACK.

### Start byte (`0x08007d96`–`0x08007dc2`)

```c
while (read_byte_with_timeout() != 0x01) { /* timeout -> leave_bootloader() */ }
aes_init();          /* fcn.08007c2c */
send(0x06);
addr = 0x08000000;   /* r6 */
seq  = 0;            /* r5 */
nak  = 0;            /* r4 */
```

The reply to `0x01` is also `0x06`.

---

## 5. Block loop (`0x08007dce`–`0x08007f00`)

```c
for (;;) {
    for (i = 0; i < 0x46; i++)                 /* 70 bytes, no timeout */
        pkt[i] = usart_read_blocking();

    seq++;                                     /* firmware-local 8-bit counter */
    if (pkt[0] != seq)          goto nak;
    if (pkt[1] != (uint8_t)~seq) goto nak;

    crc = crc16_xmodem(pkt, 64);               /* see §7 */
    if (pkt[0x43] != (crc >> 8)) goto nak;
    if (pkt[0x44] != (crc & 0xff)) goto nak;

    aes_cbc_decrypt(pkt + 3, 64);              /* in place, see §8 */

    if ((addr & 0x3ff) == 0) {                 /* 1 KiB page boundary */
        flash_unlock();
        flash_erase_page(addr);
        FMC->CTL |= 0x80;                      /* lock */
    }
    flash_unlock();
    for (p = addr; p < addr + 64; p += 2) {
        uint16_t hw;
        if      (p == 0x08000004) hw = 0x7801; /* reset vector -> bootloader */
        else if (p == 0x08000006) hw = 0x0800;
        else                      hw = pkt[3 + (p - addr)] | (pkt[4 + (p - addr)] << 8);
        flash_program_halfword(p, hw);
    }
    FMC->CTL |= 0x80;                          /* lock */

    for (p = addr; p < addr + 64; p++)         /* readback verify */
        if (p > 0x08000007 && *(uint8_t *)p != pkt[3 + (p - addr)]) goto nak;

    send(0x06);
    addr += 64;
    nak = 0;
    goto next;

nak:
    send(0x15);
    if (++nak > 0xc8) break;                   /* 200 consecutive NAKs -> give up */

next:
    if (pkt[0x45] == 0x04) break;              /* last-block marker terminates */
    if (addr > 0x080073ff) break;              /* application region exhausted */
}
leave_bootloader();
```

Points of difference from the host-side document:

- **There is a retry cap, on the device.** `0x08007ef0`: `cmp r4, 0xc8`. The protocol doc's
  §4 note "no retry limit — a device that NAKs forever hangs the loop" is true of `FD.exe`
  only; the servo stops after 200 consecutive failures and jumps to the application.
- **Writes are positional, not indexed.** `addr` starts at `0x08000000` and advances 64 bytes
  per *accepted* block. `pkt[0]`/`pkt[1]` are only a sanity check against a lost or duplicated
  block; they are never used to compute an address. A NAK does not advance either counter, so
  the host's "resend block *i*" behaviour lines up.
- **`fileFlag` (`pkt[2]`) is ignored** by the device — it is only ever consumed as part of the
  CRC input (§7).
- The application region ends at `0x080073ff`, so a valid image is at most 29 KiB / 464 blocks.
  The bootloader itself at `0x08007800` cannot be overwritten.

---

## 6. Reset-vector patch

While programming the first block the two halfwords at `0x08000004` and `0x08000006` are
replaced with `0x7801` and `0x0800`, i.e. reset vector = `0x08007801`. The readback verify
then skips every address `<= 0x08000007` (`0x08007e9e`: `cmp sl, 0x08000007 / bls`), because
those bytes deliberately no longer match the image.

The consequence: the application's own reset handler address, as shipped in the image, is
discarded. The application must therefore start at the fixed address `0x080000cc`, which is
what `fcn.08007ce8` calls.

---

## 7. CRC — the anomalous region is confirmed

`0x08007df6`–`0x08007e38`:

```asm
movw ip, 0x1021                 ; polynomial
movs r1, 0                      ; byte index
mov  r3, r1                     ; crc = 0
loop_byte:
  movs r2, 8
  ldrb.w r0, [r8, r1]           ; r8 = 0x20000320 = FRAME BASE, not the data field
  eor.w  r0, r3, r0, lsl 8
  ...                           ; 8x shift/xor, MSB-first, no reflection
  adds r1, 1
  cmp  r1, 0x40                 ; 64 bytes
  bne  loop_byte
cmp.w lr, r3, lsr 8             ; pkt[0x43] == crc_hi
ldrb.w r2, [r8, 0x44]           ; pkt[0x44] == crc_lo
```

CRC-16/XMODEM (init 0, poly `0x1021`, no reflection, no xorout), transmitted high byte first.
Confirms the protocol doc's §5 parameters.

**The ⚠ open question in §5/§9 is answered: the odd region is real.** The device computes the
CRC over `pkt[0..63]` — `seq`, `~seq`, `fileFlag` and only the **first 61 payload bytes**. The
last three payload bytes (`pkt[64..66]`) are not covered by the CRC on this path. A
reimplementation must reproduce this exactly; the natural reading (CRC over the 64 data bytes)
will be rejected by the servo.

The CRC is computed over the **ciphertext**, before decryption.

---

## 8. The payload is encrypted — AES-256-ECB

Not mentioned in the host-side document, because `FD.exe` never decrypts anything: it streams
the `.bin` file verbatim and the file on disk is already ciphertext.

After the CRC check, `0x08007e3a`:

```asm
ldr r0, [0x08007f24]      ; 0x20000323 = pkt + 3
bl  fcn.08007c98          ; r1 is still 0x40 from the CRC loop = length 64
```

`fcn.08007c98` decrypts in 16-byte blocks:

```c
for (n = len; n; n -= 16) {
    p = buf + (len - n);
    memcpy(0x20000120, p, 16);            /* fcn.08007af4 — saved, but never chained */
    aes_decrypt_block(p, key_schedule);   /* fcn.08007bdc */
    xor_into(p, iv=0x20000110, 16);       /* fcn.08007ad6 — iv is all-zero, so a no-op */
}
```

It is written in a CBC shape, but the "IV" buffer at `0x20000110` is zeroed once by
`fcn.08007c2c` and **never updated** — the saved ciphertext goes to `0x20000120` and is never
copied back into the IV. So every block is XORed with zeros, i.e. this is **AES-256-ECB**.
(Confirmed empirically below; a true CBC decode of the vendor image stays at ~7.99 b/byte
entropy while ECB drops to 6.90.)

Key material:

- `fcn.08007b0c` copies **32 bytes from `0x08007f81`** as the key and the last key word from
  `0x08007f9d` as the schedule seed → **AES-256**.
- `fcn.08007bdc` starts the round keys at `key + 0xe0` (offset 224) and walks down to
  `key + 0x00` → 14 rounds, confirming AES-256 and the equivalent-inverse-cipher form.
- `fcn.08007900` / `fcn.08007934` build the S-box and inverse S-box at runtime from the
  `0x1b` field polynomial and the `0x63` affine constant (so there are no S-box tables in the
  image to grep for).

The key bytes live at `0x08007f81`, directly after the `"1fBVA"` string at `0x08007f7c`.
Recovered from the flash dump (`flash_full_64k.bin`, file offset `0x7f81`):

```
d1 84 1f 7c 20 36 25 58 21 70 f3 87 35 a8 76 ed
ee ba 3a 74 26 e9 a0 29 56 a2 48 37 1a c0 38 2b
```

Hex: `d1841f7c203625582170f38735a876edeeba3a7426e9a02956a248371ac0382b`. The constant runs
`0x7f81..0x7fa0` and is followed by `0xFF` erase padding at `0x7fa1`, confirming a 32-byte
(AES-256) key.

Implication for any reimplementation: replaying a vendor `.bin` works without the key, but
uploading *custom* code requires encrypting it as **AES-256-ECB** with the key at
`0x08007f81` (each 16-byte block independent — no IV, no chaining).

---

## 9. Byte-level response behaviour (`fcn.08007f44`)

Half-duplex single-wire handling around every transmitted byte:

```c
USART1->CTL0 &= ~4;                     /* RE off  */
USART1->CTL0 |=  8;                     /* TE on   */
while (!(USART1->STAT & TBE)) ;
USART1->TDATA = b;
while (!(USART1->STAT & TC)) ;
USART1->CTL0 &= ~8;                     /* TE off  */
USART1->CTL0 |=  4;                     /* RE on   */
```

Only three values are ever sent: `0x06` (preamble ACK, start-byte ACK, block ACK) and `0x15`
(NAK). There is no status packet and no error code — consistent with the host's "read one raw
byte" path for non-PWM devices (protocol doc §6).

---

## 10. Application-side entry into the bootloader

`fcn.08002590` is the SCS instruction dispatcher (instruction byte at object offset `+0x109`).
It branches on `1,2,3,4,5,6,8,9,0xa,0xb,0x82,0x83`. Case `8` (`0x0800259c` → `0x080025f8`):

```asm
ldr r3, [r0]        ; vtable
ldr r3, [r3, 8]     ; slot 2
blx r3
```

So instruction `0x08` — the protocol doc's "enter firmware-update mode" — is a virtual call,
presumably ending in a system reset, which then lands in the bootloader via the patched reset
vector. Instructions `0x09` and `0x0B` (§9 open question 3) are also dispatched here, at
`0x08002642` and `0x08002652`, and are separate from the update path.

---

## 11. Corrections and additions to FIRMWARE_UPDATE_PROTOCOL.md

1. §5 ⚠ / §9 item 1 — **resolved.** The non-`.xbin` CRC region really is `pkt[0..63]`. No
   hardware test needed.
2. §9 item 2 — **resolved.** The bytes read back after the preamble and after `0x01` are both
   plain `0x06` ACKs.
3. §4 — the "no retry limit" caveat applies to the host only; the device caps at 200 NAKs.
4. **New:** payload is **AES-256-ECB** encrypted (a CBC-shaped routine whose IV is never
   chained, so it reduces to ECB), key at `0x08007f81`. Verified against the vendor image.
5. **New:** the device rewrites the reset vector to `0x08007801` and expects the application
   entry at the fixed address `0x080000cc`.
6. **New:** image size limit is the application region `0x08000000`–`0x080073ff`, not the host's
   128 KiB check — 464 blocks maximum.
7. **New:** `fileFlag` (frame byte 2) is not interpreted by the device; it only affects the CRC.
8. §9 item 4 — the device does not reset itself after the last block; it jumps straight to the
   freshly written application via `0x080000cc`.

## 12. Still open

- ~~The exact 32 key bytes at `0x08007f81`.~~ **Recovered** — see §8.
- What the instruction `0x08` vtable slot does before the reset — needs the class the
  dispatcher operates on.
- Whether `pkt[0x45]` values other than `0x04` / `0x06` mean anything (only `0x04` is tested).
- Whether the same bootloader ships on the `.fbin` / `.mbin` / `.xbin` device families — this
  image only implements the `"1fBVA"` bus-servo path.

---

## 13. Verification — the key decrypts a real vendor image

Test target: the STS3215 image (model key 9.3, `SCServo21-GD32-TTL-250306.bin`, fw 3.10, 16816 bytes,
a whole number of AES blocks). This is the ciphertext `FD.exe` streams to the servo.

Decrypting it with the recovered key as **AES-256-ECB** yields a valid firmware image:

| Check | Result |
|---|---|
| `E_key(0¹⁶)` | `9f7f0a29ff25244db8121f9eaf778f47` — matches the pre-existing known-plaintext oracle |
| ciphertext block `@0x10` | equals that oracle → plaintext there is 16 zero bytes (it is) |
| initial SP (`word[0]`) | `0x20001000` — top of SRAM, valid |
| reset vector (`word[1]`) | `0x080000cd` = `0x080000cc | thumb` — **the exact app-entry the bootloader jumps to** (`fcn.08007ce8`) |
| exception handlers | `0x0800027d`, thumb bit set; reserved slots `word[4..10]` zero |
| entropy | ciphertext 7.99 b/byte → plaintext **6.90** b/byte (ECB); CBC/zero-IV stays 7.99, i.e. wrong |

The reset-vector match is the strongest single result: `0x080000cc` was derived independently
from the bootloader disassembly (§2, §6) as the hardcoded application entry, and the decrypted
image's own reset vector points there. Two separate reverse-engineering paths converge on the
same address, so the key, the cipher (ECB), and the entry-point analysis are all confirmed
together.

Reproduce:

```bash
python3 ftfw.py pull 9.3 -o out/      # download from the vendor server, then decrypt + verify
```

`ftfw.py` decrypts with AES-256-ECB and auto-checks both the `E(0^16)` oracle and the vector
table. To decrypt a file you already have, use `python3 ftfw.py decrypt <file> -o <out>` or the
lower-level `decrypt.py --cipher aes-256 --key <key> --in <file> --out <out>`.
