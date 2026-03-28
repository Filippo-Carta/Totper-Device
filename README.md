# ESP32 TOTP Firmware

TOTP (Time-based One-Time Password) generator running on an ESP32-C3, controlled via USB serial from the companion Android app. No WiFi, no cloud, no internet connection required at any point.

[![License: CC BY-NC-ND 4.0](https://img.shields.io/badge/License-CC_BY--NC--ND_4.0-lightgrey.svg)](https://creativecommons.org/licenses/by-nc-nd/4.0/)
[![Platform](https://img.shields.io/badge/platform-ESP32--C3--Mini-blue.svg)](https://www.espressif.com/en/products/socs/esp32-c3)
[![Standard](https://img.shields.io/badge/TOTP-RFC%206238-informational.svg)](https://datatracker.ietf.org/doc/html/rfc6238)



## Overview

TOTP secrets are stored exclusively on the physical ESP32 device in non-volatile storage (NVS). The device has no network interface — time is supplied by the Android app over USB serial each time it connects. Once synced, the ESP32 tracks elapsed time internally using its own clock, so codes remain valid for the entire session.

Access to the device is protected by a 5-digit PIN entered via two physical buttons. After 5 failed attempts, all stored accounts are permanently wiped and the device reboots.



## Hardware
All of the necessary schematic are available in the /schematic/ folder in the repository. You can print the pcb by exporting the files and sending them to a pcb manufacturer.
| Component | Details |
|---|---|
| Microcontroller | ESP32-C3 |
| Display | SSD1306 OLED, 128x32, I2C |
| Button 1 (Cycle) | GPIO 5 — cycles digits / switches account |
| Button 2 (Confirm) | GPIO 6 — confirms digit / advances to next |
| I2C SDA | GPIO 4 |
| I2C SCL | GPIO 3 |


## Dependencies

Install these libraries via the Arduino Library Manager or PlatformIO:

- [Adafruit SSD1306](https://github.com/adafruit/Adafruit_SSD1306)
- [Adafruit GFX Library](https://github.com/adafruit/Adafruit-GFX-Library)
- `Preferences` — built into the ESP32 Arduino core
- `mbedtls/md.h` — built into the ESP32 Arduino core

## Security Warning

This firmware stores TOTP secrets in ESP32 NVS flash **in plaintext**. NVS is not encrypted by default.

This means that anyone with physical access to the device and a USB connection can dump the entire flash contents using standard tools and read every stored secret directly — regardless of the PIN. The PIN only protects the serial interface. It does not protect the flash memory itself.

**If you do not enable flash encryption, physical possession of the device is equivalent to full access to all your TOTP secrets.**

Without flash encryption this device should be treated as a convenience tool only, not as a secure hardware token. With flash encryption enabled, physical attacks become significantly harder.

## Serial Protocol

Communication runs at **115200 baud, 8N1** over USB CDC. All commands are newline-terminated (`\n`).

| Command | Response | Auth required |
|---|---|---|
| `TIME <unix>` | `OK:time_set:<unix>` | No |
| `STATUS` | `OK:ready:<n>` | Yes |
| `LIST` | JSON array `[{index, name}, ...]` | Yes |
| `ADD <n> <base32>` | `OK:added:<idx>:<n>` | Yes |
| `REMOVE <idx>` | `OK:removed:<idx>:<n>` | Yes |
| `CLEAR` | `OK:cleared` | No |

Any command requiring auth while the device is locked returns `ERR:locked`.

`TIME` and `CLEAR` are always permitted regardless of lock state. `CLEAR` wipes all accounts and reboots the device.

### Constraints

- Account name: maximum 12 characters
- Base32 secret: minimum 8 characters, uppercase, standard Base32 alphabet



## PIN System

The PIN is 5 digits, entered using the two physical buttons:

- **Cycle button** — increments the current digit (0-9, wraps around)
- **Confirm button** — confirms the digit and advances to the next position

On first boot, the device enters a PIN setup flow before doing anything else. The PIN is stored in NVS alongside the accounts.

To change the PIN, hold the **Confirm button** while powering on the device. The change flow requires the current PIN before setting a new one.

After **5 consecutive wrong PIN attempts**, all data is wiped via `nvsClearAll()` and the device restarts.


## Time Sync

The device has no RTC and no network access. On every USB connection, the Android app sends:

```
TIME <unix_seconds>
```

The firmware records the Unix timestamp and the value of `millis()` at that moment. From then on, the current time is calculated as:

```
currentTime = baseUnix + (millis() - baseMillis) / 1000
```

Until a `TIME` command is received, the display shows "Waiting for time sync" and no TOTP codes are generated.


## TOTP Implementation

The firmware implements RFC 6238 using HMAC-SHA1 from the mbedTLS library (bundled with the ESP32 Arduino core). The time step is 30 seconds and codes are 6 digits.

```
counter = currentTime / 30
TOTP    = HOTP(secret, counter)
```


## NVS Storage Layout

All data is stored under the `totp` namespace in NVS flash.

| Key | Type | Description |
|---|---|---|
| `pin` | String | 5-digit PIN |
| `count` | Int | Number of stored accounts |
| `name_N` | String | Account name at index N |
| `sec_N` | String | Base32 secret at index N |
| `fail_cnt` | Int | Consecutive failed PIN attempts |


## Companion App

The Android app that communicates with this firmware is available at:

[https://github.com/filippo-carta/Totper](https://github.com/Filippo-Carta/Totper)



## License

Copyright Filippo Carta — [CC BY-NC-ND 4.0](https://creativecommons.org/licenses/by-nc-nd/4.0/)

Free to use and share with attribution. Modification and commercial use are not permitted.


## HAVE FUN!
