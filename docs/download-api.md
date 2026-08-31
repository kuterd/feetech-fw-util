# FEETECH firmware download API

The FEETECH updater (`FD.exe`) fetches firmware from the vendor's own update
server over plain HTTP. The endpoints and the key format were recovered from the
`FD.exe` disassembly, not guessed. `ftfw.py` speaks this API directly.

## Endpoints

Two endpoints, both plain HTTP on port 9048, both returning JSON:

```
http://www.scservo.com:9048/ftgetzuixinbanben/<appname>    version check
http://www.scservo.com:9048/ftgetzuixinwenjian/<key>       file fetch
```

(`banben` = 版本 version, `wenjian` = 文件 file, `xinghao` = 型号 model.)

## The model key

The file key is built in `FD.exe` at `fcn.00410d80` (`0x00410e72`–`0x00410f0c`):

```c
/* entry = servo_list[selected]; 9 bytes per entry */
sprintf(model_str,  "%d.%d", entry[3], entry[4]);   /* servo main.sub version */
sprintf(fw_version, "%d.%d", entry[0], entry[1]);   /* firmware main.sub      */

if (class_char == ' ')                              /* bus servo              */
    sprintf(url, ".../ftgetzuixinwenjian/%s",   model_str);
else                                                /* f=pwm m=modbus x=open  */
    sprintf(url, ".../ftgetzuixinwenjian/%c%s", class_char, model_str);
```

So the key is literally the servo's **Servo Main Version . Servo Sub Version**,
read from EEPROM addresses **3** and **4**. `entry[0].entry[1]` is the
*installed* firmware version, compared against `banben` to decide whether an
update exists.

A third form, `s%d.%d`, appears at `0x0040da9a`; every `s<model>` key tested
returns `没有数据` ("no data") — that path is dead on the current server.

> **Read the key off the actual servo.** Use the Qt tool or FD to read EEPROM
> address 3 (Servo Main Version) and address 4 (Servo Sub Version). If they don't
> match the key you intend to flash, it's the wrong image.

## Response shape

```json
{"status":200,"message":null,
 "data":{"id":100898,"banben":"3.10","xinghao":"9.3",
         "filename":"SCServo21-GD32-TTL-250306.bin",
         "wenjian":"<base64>"}}
```

Missing keys return `{"status":500801,"message":"没有数据","data":null}`.
`wenjian` is base64; decode it to get the (still-encrypted) `.bin`.

## Catalog

Enumerating `<major>.<minor>` over 0–20 × 0–20 (441 keys) yields 33 hits and 10
distinct files. The whole 9.2–9.11 range is served the **same** byte-identical
image — one firmware covers the STS family.

| Model keys | Version | File | Size |
|---|---|---|---|
| 6.16, 6.20 | 1.6 | SMServo1.0-STM32-485(200710).bin | 12,992 |
| 8.0 | 2.53 | SMServo2.40-STM32-485(220714).bin | 19,552 |
| **9.2–9.11** | **3.10** | **SCServo21-GD32-TTL-250306.bin** | **16,816** |
| 9.15 | 3.24 | SCServo2.20-GD32-TTL(200824).bin | 10,720 |
| 10.0 | 20.8 | SMServo3.40-STM32-485-MODBUS(220715).mbin | 17,712 |
| 10.3 | 3.41 | FT-HTS-GD32-TTL-240319.bin | 17,936 |
| 10.4, 10.7 | 3.42 | FT-HTS-GD32-TTL-241125.bin | 18,064 |
| 10.6, 10.9 | 3.20 | STServo3.20-STM32-TTL(220714).bin | 19,344 |
| 10.8, 10.10–10.20 | 3.43 | FT-HLS-GD32-TTL-250326.bin | 17,632 |
| 13.1 | 8.2 | LY-TTLSD-CW32-TTL-260718.bin | 18,304 |

Note `10.6`/`10.9` is `STServo3.20-STM32-TTL` — despite the "STServo" name it is
*not* the ST3215 image; the model table puts 10.x elsewhere.

## The payloads are encrypted

The served `.bin` is **not** a flashable image — it is AES-256-ECB ciphertext.
`FD.exe` never decrypts it; it base64-decodes `wenjian` and streams the bytes
verbatim to the servo, whose **bootloader decrypts in place**. Evidence, and the
full flashing protocol, are in
[`firmware-update-protocol.md`](firmware-update-protocol.md) (host side) and
[`bootloader-analysis.md`](bootloader-analysis.md) (device side); the key and its
verification are in §8 and §13 of the latter.

Tell-tales of the encryption, visible without the key:

- every file's length is an exact multiple of 16;
- the 16 bytes at offset `0x10` are identical in every file:
  `9f7f0a29ff25244db8121f9eaf778f47` = `E(0^16)`, the encryption of the all-zero
  reserved vector slots — a known-plaintext oracle for the key;
- repeated 16-byte blocks occur *within* files, the signature of ECB mode.

## Reproducing a raw fetch

```bash
curl -s "http://www.scservo.com:9048/ftgetzuixinwenjian/9.3" \
  | python3 -c "import sys,json,base64;d=json.load(sys.stdin)['data'];open(d['filename'],'wb').write(base64.b64decode(d['wenjian']));print(d['filename'],d['banben'])"
```

That writes the encrypted `.bin`. Then `decrypt.py`, or just use
`ftfw.py pull 9.3` to do both at once.
