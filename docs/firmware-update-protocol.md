# FEETECH firmware update protocol — host side

How `FD.exe` (FD 1.9.8.3) drives a servo through a firmware update. Addresses are
virtual addresses in that binary. The device side is in
[`bootloader-analysis.md`](bootloader-analysis.md); the vendor download API in
[`download-api.md`](download-api.md).

An update is five steps: enter the bootloader, send a magic preamble, send a start
byte, stream the image as fixed 70-byte block frames (each ACKed or NAKed), then
restore the baud rate. The payload is AES-256-ECB ciphertext — FD streams the
`.bin` verbatim and the servo decrypts each block into flash as it arrives.

---

## 1. Function map

| Address | Role |
|---|---|
| `0x004100b0` | Upgrade worker-thread proc — selects the preamble, calls the transfer loop |
| `0x0040ff60` | Transfer loop |
| `0x0040fe50` | Enter bootloader / switch baud |
| `0x0040fc80` | Build one 70-byte block frame |
| `0x0040fd70` | Send a buffer, read one response code |
| `0x0040fd50` | Block count = `ceil(u16 @ buf[0] / 64)` |
| `0x00410200`… | File-open handler; loads the image and sets the mode flags |
| `0x00412f50` | CRC-16 engine (table-less, bit-at-a-time) |
| `0x00413050` | CRC-16 constructor |
| `0x00416e20` | SCS instruction packet builder (`write_buf` equivalent) |
| `0x00416850` | `SetCommState` wrapper — baud/parity/timeout/purge/DTR/RTS |
| `0x004167a0` | `SetCommTimeouts` wrapper (read+write total timeout, ms) |

Owning class is `CServoPG` (the Upgrade tab). Instance fields:

| Offset | Meaning |
|---|---|
| `+0x20c` | Firmware image buffer: `u16` length header, then up to `0x20000` bytes |
| `+0x238` | Selected servo ID (`-1` = none) |
| `+0x240` | `fileFlag` — byte 2 of every block frame |
| `+0x244` | `1` for `.xbin` only — selects DTR/RTS entry and the CRC region |
| `+0x248` | Total block count |
| `+0x24c` | Device class: 0 = bus, 1 = PWM, 2 = Modbus |
| `+0x6b0` | CRC-16 object |

---

## 2. Loading the image

`0x0041060b`, raw `.bin` family:

```c
size = file.length();
if (size > 0x20000) { error("file too large"); return; }   // 128 KiB
memset(fw + 2, 0xFF, 0x20000);      // 0x0043bc40 = memset
file.read(fw + 2, size);
*(uint16_t *)fw = (uint16_t)size;   // little-endian length header
```

The two-byte header is synthesized by the host, not part of the `.bin` on disk.
Payload starts at `fw[2]`; the buffer is pre-filled with `0xFF`, so the last
partial block is `0xFF`-padded. FD streams these bytes verbatim — the vendor
`.bin` is already ciphertext, and a self-built plaintext image must be
AES-256-ECB encrypted before it can be flashed (key in
[`bootloader-analysis.md`](bootloader-analysis.md) §8).

Block count (`0x0040fd50`):

```c
n_blocks = size / 64; if (size % 64) n_blocks++;
```

Block *n* (1-based) covers `fw[2 + (n-1)*64 .. 2 + n*64 - 1]` (`fw + (n << 6) -
0x3e` in the disassembly).

The size check permits `0x20000` but the header is a `uint16`, so a file ≥ 65536
bytes writes a truncated length — cap at 65535. The servo's application region is
smaller anyway (~29.5 KiB / 464 blocks on the GD32 part).

`.hex` files take a separate path (`0x004135c0`, an Intel-HEX parser, then a
merge/sort at `0x004134c0`), not covered here.

---

## 3. File extension selects the device class

`0x00410686`–`0x004106e2`:

| Extension | Device | `+0x240` | `+0x244` | `+0x24c` |
|---|---|---|---|---|
| `.bin` | bus servo | 1 | 0 | 0 |
| `.hex` | bus servo | 0 | 0 | 0 |
| `.fbin` | PWM device | 1 | 0 | 1 |
| `.mbin` | Modbus device | 1 | 0 | 2 |
| `.xbin` | open device | 1 | 1 | 0 |

These flags drive every branch below.

---

## 4. Sequence

### Step 1 — enter the bootloader (`0x0040fe50`)

Returns the previous baud rate, restored when the transfer ends.

**`.xbin`** — hardware reset over the modem control lines, no packet:

```
setBaud(500000, parity=none)
CLRDTR ; SETRTS          (EscapeCommFunction 6, then 3)
Sleep(100)
SETDTR ; CLRRTS          (EscapeCommFunction 5, then 4)
setTimeout(50)
PurgeComm(PURGE_RXCLEAR)
repeat up to 20x: read 1 byte; stop on 'C' (0x43)
setTimeout(500)
```

The `'C'` poll is advisory — the code proceeds regardless. `setBaud` already
leaves DTR asserted and RTS deasserted (§6), so the toggle is: assert reset, hold
100 ms, release. Line polarity is at the Win32 API level: `SETDTR` drives the
logical signal true, which on a USB-serial bridge normally pulls the physical pin
low.

**Everything else** — send a wake-up packet, then switch baud:

| Device | Wake-up | New baud |
|---|---|---|
| bus (`.bin`, `.hex`) | SCS packet to the ID, instruction `0x08`, no parameters | 500000 |
| PWM (`.fbin`) | SCS packet to `0xFE` broadcast, instruction `0x0D`, no parameters | unchanged |
| Modbus (`.mbin`) | Modbus frame to the ID, function code `0x41` | 500000 |

```
send wake-up packet
Sleep(15)                 // bus and Modbus only
setBaud(newBaud, parity=none)
Sleep(100)
setTimeout(500)
```

Bus-servo wake-up packet:

```
FF FF <id> 02 08 <~(id + 0x02 + 0x08)>
```

### Step 2 — magic preamble (`0x004100b0`)

Five ASCII bytes, written once. The servo replies with `0x06`; FD reads one byte
and checks only for a timeout.

| Device class | Bytes |
|---|---|
| `.xbin` (`+0x244 == 1`) | `"ABV1f"` = `41 42 56 31 66` |
| `.bin`, `.hex`, `.mbin` | `"1fBVA"` = `31 66 42 56 41` |
| `.fbin` | skipped |

Skip condition (`0x0040ff9f`): send unless `+0x24c == 1 && +0x244 != 1`, i.e. the
`.fbin` case.

### Step 3 — start byte

Send `0x01`, read one response (`0x0040ffe7`). The servo replies `0x06`; a timeout
aborts, any other value is accepted.

### Step 4 — block loop (`0x0040ff60`)

```c
for (i = 1; i <= n_blocks; ) {
    build_frame(pkt, i, (i == n_blocks) ? 0x04 : 0x06, fileFlag, is_xbin);
    r = send_and_read_one(pkt, 70);
    if      (r == 0x06) { progress++; i++; }   /* ACK  */
    else if (r == 0x15) { /* NAK: resend i */ }
    else                { fail(); break; }     /* incl. timeout (-1) */
}
setBaud(previousBaud, previousParity);
```

There is no EOT; the `0x04` in byte 69 of the last frame ends the transfer. FD
imposes no NAK retry limit, so a reimplementation should add one (the servo itself
stops after 200 consecutive NAKs).

---

## 5. Block frame — 70 bytes (`0x0040fc80`)

```
offset  size  contents
------  ----  ------------------------------------------------------
  0       1   seq       block index, 1-based, truncated to 8 bits
  1       1   ~seq      one's complement of byte 0
  2       1   fileFlag  field +0x240 (1 for .bin/.fbin/.mbin/.xbin, 0 for .hex)
  3      64   data      64 payload bytes, 0xFF-padded in the last block
 67       1   crc_hi
 68       1   crc_lo
 69       1   0x04 on the last block, 0x06 otherwise
------  ----  ------------------------------------------------------
total    70   (0x46)
```

No SOH, no length field; the frame is fixed-size.

### CRC region

```c
crc = crc16_xmodem(is_xbin ? pkt + 3 : pkt + 0, 64);   /* length always 64 */
```

- `.xbin` → CRC over the 64 data bytes (`pkt[3..66]`).
- everything else → CRC over `pkt[0..63]` — `seq`, `~seq`, `fileFlag` and the
  first 61 data bytes only; the last three data bytes are not covered.

The disassembly is unambiguous (`0x0040fd0c`: `cmp arg4, 1` / `lea eax, [esi+3]`
vs `push esi`, `push 0x40` in both branches). The CRC is over the ciphertext,
before the servo decrypts.

### CRC parameters

`0x00413050`: **CRC-16/XMODEM** — `init=0x0000, xorout=0x0000, poly=0x1021,
reflect=false`, MSB-first, high byte transmitted first.

```c
uint16_t crc16_xmodem(const uint8_t *p, size_t n)
{
    uint16_t crc = 0x0000;
    while (n--) {
        crc ^= (uint16_t)(*p++) << 8;
        for (int i = 0; i < 8; i++)
            crc = (crc & 0x8000) ? (uint16_t)((crc << 1) ^ 0x1021)
                                 : (uint16_t)(crc << 1);
    }
    return crc;
}
```

The engine at `0x00412f50` also has a reflected variant, unused here.

---

## 6. Transport details

### Response framing (`0x0040fd70`)

- **PWM (`.fbin`)**: write the buffer, read a 7-byte SCS status packet, take byte 5
  as the response code (`FF FF id len err <code> chk`).
- **Everything else**: purge RX, write the buffer, read one raw byte.

The code is compared against `0x06` / `0x15`; a short or timed-out read yields
`-1` → failure path.

### `setBaud` (`0x00416850`)

Each call also:

- `SetupComm(handle, 1024, 1024)` — 1 KiB RX/TX buffers
- recomputes the read/write timeout as `1400832 / baud + margin` ms
- `GetCommState`, then sets `BaudRate`, `ByteSize = 8`, `Parity` from the argument
- forces `fDtrControl = DTR_CONTROL_ENABLE`, `fRtsControl = RTS_CONTROL_ENABLE`
  (`&= ~0x2020; |= 0x1010`)
- `SetCommState`
- `PurgeComm(PURGE_TXCLEAR | PURGE_RXCLEAR)`
- `SETDTR` then `CLRRTS`

and returns the previous baud rate (previous parity stashed at `serial+0x414`).

The derived timeout is overwritten by the explicit `setTimeout(500)` at the end of
bootloader entry, so the transfer read/write timeout is 500 ms; the `.xbin` `'C'`
poll runs at 50 ms.

### Instruction set (`0x00416e20`)

`FF FF <id> <len> <inst> [addr] [data…] <~sum>`; `len = 2` with no parameters or
`data_len + 3` with them; checksum over `len + id + addr + inst + data`.

| Inst | Meaning |
|---|---|
| `0x01` | PING |
| `0x02` | READ |
| `0x03` | WRITE |
| `0x04` | REG_WRITE |
| `0x05` | ACTION |
| `0x06` | RESET |
| `0x08` | enter firmware-update mode (bus servo) |
| `0x09` | unidentified, no parameters |
| `0x0B` | unidentified, no parameters |
| `0x0D` | enter firmware-update mode (PWM device, broadcast) |

`0x08`, `0x09`, `0x0B`, `0x0D` are undocumented in the published SCS protocol.

---

## 7. Failure handling and recovery

Any response other than `0x06` / `0x15` aborts the loop ("Firmware upgrade
failed"); the baud rate is still restored. There is no abort or recovery packet,
so a failed update leaves the servo in the bootloader.

This is recoverable: the bootloader points the application reset vector at itself,
so any reset re-enters it, and re-running the update from a clean preamble
restores the servo. On success the bootloader jumps straight to the application
(fixed entry `0x080000cc`) — no reset or power cycle needed.

---

## 8. Porting to `FT_SCServo_Debug_Qt`

The Qt port has no upgrade code. To implement the `.bin` path:

1. **Instructions `0x06`, `0x08`, `0x09`, `0x0B`, `0x0D`** — `servo/scserial.h:8`
   stops at `INST_REG_WRITE`/`INST_REG_ACTION`. `SCSerial::write_buf()` takes the
   instruction as a parameter, so bootloader entry is
   `write_buf(id, 0, NULL, 0, 0x08)`.
2. **CRC-16/XMODEM** — nothing computes a CRC today; mind the `pkt[0..63]` region
   for the bus path (§5).
3. **Frame builder and transfer loop** — no equivalent of `0x0040fc80` /
   `0x0040ff60`.
4. **Mid-session baud switching** — `mainwindow.cpp:322` sets baud once at open;
   the transfer needs 500000 and a restore. On Linux/CH340 verify
   `QSerialPort::setBaudRate(500000)` against the adapter.
5. **DTR/RTS control** — `.xbin` only;
   `setDataTerminalReady()` / `setRequestToSend()`.
6. **Read timeout** — `SCSerial::read()` hardcodes `waitForReadyRead(100)`; the
   transfer needs 500 ms and the `'C'` poll 50 ms.
7. **AES-256-ECB encryption** — encrypt a self-built image before framing (§2);
   vendor `.bin`s stream as-is.
8. **Intel HEX parsing** — only if `.hex` support is wanted.

---

## 9. Scope and unknowns

This was read from disassembly, not run on hardware. The device side was verified
only for the bus-servo (`.bin`, `"1fBVA"`) path; the `.xbin` / `.fbin` / `.mbin`
paths — including the `.xbin` DTR/RTS line polarity — are as described by FD but
not cross-checked against a device. The behavior of instructions `0x09` and
`0x0B`, the `.hex` path, and the Modbus (`.mbin`) framing beyond function code
`0x41` are unknown.
