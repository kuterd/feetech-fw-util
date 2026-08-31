# FEETECH firmware update protocol

Reverse-engineered from `FD.exe` (FD 1.9.8.3, PE32 x86, MFC9, built 2023-12-05).
All addresses below are virtual addresses in that binary; disassembly lives in
`disasm/FD/`, one file per function under `disasm/FD/functions/asm/`.

Everything here was read out of the disassembly. **Nothing has been tested against
hardware.** Items flagged ⚠ are the ones most likely to be wrong.

---

## 1. Function map

| Address | Role |
|---|---|
| `0x004100b0` | Upgrade worker-thread proc — selects the magic preamble, calls the transfer loop |
| `0x0040ff60` | Transfer loop (the main event) |
| `0x0040fe50` | Enter bootloader / switch baud |
| `0x0040fc80` | Build one 70-byte block frame |
| `0x0040fd70` | Send a buffer, read one response code |
| `0x0040fd50` | Block count = `ceil(u16 @ buf[0] / 64)` |
| `0x00410200`… | File-open handler; loads the image and sets the mode flags |
| `0x00412f50` | CRC-16 engine (table-less, bit-at-a-time) |
| `0x00413050` | CRC-16 constructor — pins the parameters |
| `0x00416e20` | SCS instruction packet builder (`write_buf` equivalent) |
| `0x00416850` | `SetCommState` wrapper — baud/parity/timeout/purge/DTR/RTS |
| `0x004167a0` | `SetCommTimeouts` wrapper (read+write total timeout, in ms) |

The owning class is `CServoPG` (the Upgrade tab). Relevant instance fields:

| Offset | Meaning |
|---|---|
| `+0x20c` | Firmware image buffer: `u16` length header, then up to `0x20000` bytes |
| `+0x238` | Selected servo ID (`-1` = none) |
| `+0x240` | `fileFlag` — transmitted in byte 2 of every block frame |
| `+0x244` | `1` for `.xbin` only — selects DTR/RTS entry **and** the CRC region |
| `+0x248` | Total block count |
| `+0x24c` | Device class: 0 = bus, 1 = PWM, 2 = Modbus |
| `+0x6b0` | CRC-16 object |

---

## 2. Loading the image

From `0x0041060b` (raw `.bin` family):

```c
size = file.length();
if (size > 0x20000) { error("file too large"); return; }   // 128 KiB
memset(fw + 2, 0xFF, 0x20000);      // 0x0043bc40 = memset
file.read(fw + 2, size);
*(uint16_t *)fw = (uint16_t)size;   // little-endian length header
```

So the two-byte header is **synthesized by the host application** — it is not part
of the `.bin` file on disk. Payload starts at `fw[2]`. The buffer is pre-filled
with `0xFF`, so the final partial block is `0xFF`-padded.

Block count (`0x0040fd50`):

```c
n_blocks = size / 64; if (size % 64) n_blocks++;
```

Block *n* (1-based) covers `fw[2 + (n-1)*64 .. 2 + n*64 - 1]`. In the disassembly
this appears as `fw + (n << 6) - 0x3e`, which is the same thing.

⚠ **Upstream bug**: the size check permits up to `0x20000` but the header is a
`uint16`. A file of 65536 bytes or more writes a truncated length and the block
count comes out wrong. Cap at 65535 in any reimplementation.

`.hex` files take a different path (`0x004135c0`, an Intel-HEX record parser
building a `CList<Hex>`, then a merge/sort pass at `0x004134c0`). Not fully
reversed — FEETECH ships `.bin`, so this was left alone.

---

## 3. File extension selects the device class

Set at `0x00410686`–`0x004106e2`:

| Extension | Device | `+0x240` | `+0x244` | `+0x24c` |
|---|---|---|---|---|
| `.bin` | bus servo | 1 | 0 | 0 |
| `.hex` | bus servo | 0 | 0 | 0 |
| `.fbin` | PWM device | 1 | 0 | 1 |
| `.mbin` | Modbus device | 1 | 0 | 2 |
| `.xbin` | open device | 1 | 1 | 0 |

These three flags drive every branch in the rest of the protocol.

---

## 4. Sequence

### Step 1 — enter the bootloader (`0x0040fe50`)

Returns the previous baud rate, restored when the transfer ends.

**`.xbin` (open device)** — hardware reset over the modem control lines, no packet:

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

The `'C'` poll is advisory — the code proceeds regardless of whether it ever
arrives. Note `setBaud` itself already leaves DTR asserted and RTS deasserted
(§6), so the toggle is: assert reset, hold 100 ms, release.

⚠ Line polarity: this is written at the Win32 API level. `SETDTR` /
`QSerialPort::setDataTerminalReady(true)` drives the *logical* signal true, which
on a USB-serial bridge normally pulls the physical pin **low**.

**Everything else** — send a wake-up packet, then switch baud:

| Device | Wake-up | New baud |
|---|---|---|
| bus (`.bin`, `.hex`) | SCS packet to the selected ID, **instruction `0x08`**, no parameters | 500000 |
| PWM (`.fbin`) | SCS packet to `0xFE` broadcast, **instruction `0x0D`**, no parameters | unchanged (keeps the current rate) |
| Modbus (`.mbin`) | Modbus frame to the selected ID, **function code `0x41`** | 500000 |

```
send wake-up packet
Sleep(15)                 // bus and Modbus only
setBaud(newBaud, parity=none)
Sleep(100)
setTimeout(500)
```

For a bus servo the wake-up packet is exactly:

```
FF FF <id> 02 08 <~(id + 0x02 + 0x08)>
```

### Step 2 — magic preamble (`0x004100b0`)

Five ASCII bytes, written once; one byte is read back and only checked for
timeout.

| Device class | Bytes |
|---|---|
| `.xbin` (`+0x244 == 1`) | `"ABV1f"` = `41 42 56 31 66` |
| `.bin`, `.hex`, `.mbin` | `"1fBVA"` = `31 66 42 56 41` |
| `.fbin` | **skipped entirely** |

The skip condition at `0x0040ff9f` is: send the preamble unless
`+0x24c == 1 && +0x244 != 1`, which is exactly the `.fbin` case.

### Step 3 — start byte

Send the single byte `0x01`, read one response (`0x0040ffe7`). A timeout aborts;
any other value is accepted.

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

There is **no retry limit** on NAK — a device that NAKs forever hangs the loop.
Add a cap. There is no EOT; the `0x04` in byte 69 of the last frame terminates the
transfer.

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

Note there is no SOH and no length field; the frame is fixed-size.

⚠ **The CRC region depends on the device class** — this is the single most
surprising detail and the most likely thing to get wrong:

```c
crc = crc16_xmodem(is_xbin ? pkt + 3 : pkt + 0, 64);   /* length always 64 */
```

- `.xbin` → CRC over the 64 **data** bytes (`pkt[3..66]`), the natural reading.
- everything else → CRC over `pkt[0..63]`, i.e. `seq`, `~seq`, `fileFlag` and only
  the **first 61 data bytes**. The last three data bytes are not covered.

The disassembly is unambiguous (`0x0040fd0c`: `cmp arg4, 1` / `lea eax, [esi+3]`
vs `push esi`, with `push 0x40` as the length in both branches), but it is odd
enough to be worth confirming on hardware before trusting it.

### CRC parameters

Constructed at `0x00413050` as `crc16(init=0x0000, xorout=0x0000, poly=0x1021,
reflect=false)` — i.e. **CRC-16/XMODEM**, MSB-first, no reflection.

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
    return crc;                 /* transmit high byte first */
}
```

The engine at `0x00412f50` also implements a reflected variant, but the reflect
flag is false here so that path is dead.

---

## 6. Transport details

### Response framing (`0x0040fd70`)

Two variants, selected by the same flags:

- **PWM (`.fbin`)**: write the buffer, then read a **7-byte SCS status packet**
  and take **byte 5** as the response code (`FF FF id len err <code> chk`).
- **Everything else**: purge RX, write the buffer, read **one raw byte**.

Either way the returned code is compared against `0x06` / `0x15`. A short or
timed-out read yields `-1`, which falls through to the failure path.

### What `setBaud` does (`0x00416850`)

Changing the baud rate is not just a baud rate change. Each call also:

- `SetupComm(handle, 1024, 1024)` — 1 KiB RX/TX buffers
- recomputes the read/write timeout as `1400832 / baud + margin` ms
- `GetCommState`, then sets `BaudRate`, `ByteSize = 8`, `Parity` from the argument
- forces `fDtrControl = DTR_CONTROL_ENABLE`, `fRtsControl = RTS_CONTROL_ENABLE`
  (bitfield `&= ~0x2020; |= 0x1010`)
- `SetCommState`
- `PurgeComm(PURGE_TXCLEAR | PURGE_RXCLEAR)`
- `SETDTR` then `CLRRTS`

and returns the previous baud rate. The previous parity is stashed at
`serial+0x414` and passed back on restore.

The derived timeout is immediately overwritten by the explicit `setTimeout(500)`
at the end of bootloader entry, so during the transfer the read/write timeout is
**500 ms**. The `'C'` poll in the `.xbin` path runs at **50 ms**.

### Instruction set (`0x00416e20`)

The standard SCS builder — `FF FF <id> <len> <inst> [addr] [data…] <~sum>`,
`len = 2` with no parameters or `data_len + 3` with them, checksum over
`len + id + addr + inst + data`. Instructions actually referenced by the binary:

| Inst | Meaning |
|---|---|
| `0x01` | PING |
| `0x02` | READ |
| `0x03` | WRITE |
| `0x04` | REG_WRITE |
| `0x05` | ACTION |
| `0x06` | RESET |
| `0x08` | **enter firmware-update mode** (bus servo) |
| `0x09` | (unidentified, no parameters) |
| `0x0B` | (unidentified, no parameters) |
| `0x0D` | **enter firmware-update mode** (PWM device, broadcast) |

`0x08`, `0x09`, `0x0B` and `0x0D` are undocumented in the published SCS protocol
and absent from every open-source Feetech library I have seen.

---

## 7. Failure handling

On any response that is neither `0x06` nor `0x15`, the loop aborts and shows
"Firmware upgrade failed". The baud rate is still restored. **The servo is left in
the bootloader** — there is no abort or recovery packet in the binary, so a failed
update leaves the device waiting for blocks. Recovery is presumably re-running the
update, since bootloader entry re-sends the preamble from a clean state.

---

## 8. Gap list against `FT_SCServo_Debug_Qt`

The Qt port has no upgrade code at all (`README.md` lists "Upgrade tab & features"
as unported). To implement the `.bin` path:

1. **Instructions `0x06`, `0x08`, `0x09`, `0x0B`, `0x0D`** — `servo/scserial.h:8`
   stops at `INST_REG_WRITE`/`INST_REG_ACTION`. `SCSerial::write_buf()` already
   takes the instruction as a parameter, so bootloader entry is
   `write_buf(id, 0, NULL, 0, 0x08)` with no other changes.
2. **CRC-16/XMODEM** — nothing in the tree computes a CRC; the SCS layer only does
   `~sum`.
3. **Frame builder and transfer loop** — no equivalent of `0x0040fc80` /
   `0x0040ff60`.
4. **Mid-session baud switching** — `mainwindow.cpp:322` sets the baud once at
   open. The transfer needs 500000 and a restore afterwards. On Linux with a CH340
   this needs the custom-divisor path; `QSerialPort::setBaudRate(500000)` should
   work on current kernels but is worth verifying against the actual adapter.
5. **DTR/RTS control** — `.xbin` only.
   `QSerialPort::setDataTerminalReady()` / `setRequestToSend()` cover it.
6. **Configurable read timeout** — `SCSerial::read()` (`servo/scserial.cpp`)
   hardcodes `waitForReadyRead(100)`. The transfer needs 500 ms and the `'C'` poll
   needs 50 ms.
7. **Intel HEX parsing** — only if `.hex` support is wanted.

## 9. Open questions

- ⚠ The non-`.xbin` CRC region (`pkt[0..63]`). Highest-risk item; verify first.
- Whether the byte read back after the `"1fBVA"` preamble and after the `0x01`
  start byte carries meaning. FD ignores the value and only checks for a timeout.
- What instructions `0x09` and `0x0B` do.
- Whether the servo needs a reset or power cycle after a successful update — FD
  only restores the baud rate.
- The `.hex` path and the Modbus (`.mbin`) framing beyond the `0x41` function code.
