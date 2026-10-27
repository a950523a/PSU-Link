# PSU-Link

The link protocol between a charging controller and the power node that supplies it —
over UART or ESP-NOW, same bytes either way.

Portable C99 with zero platform dependencies (`<stdint.h>`, `<stdbool.h>`, `<stddef.h>`
only; no `printf`/`scanf`). Both ends include this repository as a submodule, so the
wire format has exactly one definition.

| Used by | Role |
|---------|------|
| [TES Charging Controller](https://github.com/a950523a/TES-Taiwan-Electric-Scooter-Charging-Controller) | Controller: sends `HELO`, `SET` |
| [LianMing PSU Controller](https://github.com/a950523a/LianMing-PSU-Controller) | Power node: sends `CAP`, `ST`, `ACK` |

This is separate from [TES-Protocol](https://github.com/a950523a/TES-Protocol), which holds
the TES-0D-02-01 vehicle ↔ charger CAN protocol. This link never touches the vehicle.

## Wire format

```
$<TYPE>,<field>,...*<CRC16>\n
```

- One message per ASCII line; a trailing `\r` is ignored.
- CRC-16/CCITT-FALSE (poly `0x1021`, init `0xFFFF`) over the bytes between `$` and `*`,
  written as 4 hex digits.
- All values are integers; voltage and current in units of 0.01 (`4820` = 48.20 V).
- Lines that do not start with `$` are not part of the protocol. A node can keep
  accepting human text commands (`PAIR`, `ON`, …) on the same port.

| Direction | Message | Purpose |
|-----------|---------|---------|
| controller → node | `$HELO,<ver>` | Ask for capabilities; node answers `CAP` |
| node → controller | `$CAP,<ver>,<type>,<caps>,<vmax>,<imax>,<fw>` | Node type and capabilities (sent at boot and on `HELO`) |
| node → controller | `$ST,<seq>,<v>,<i>,<mode>,<flags>` | Status; every 100 ms while outputting, every 1 s idle. Doubles as the heartbeat |
| controller → node | `$SET,<seq>,<v>,<i>` | Setpoints; leave `<v>` or `<i>` empty to leave it unchanged |
| node → controller | `$ACK,<seq>,<result>` | Answer to `SET` |
| node → controller | `$PWR,<vac>,<pmax>,<ilim>,<src>` | AC input and the power the node can deliver now (sent on change, on `HELO` and every 30 s; declared by `PSU_CAP_REPORT_PWR`) |

| controller → node | `$CHN,<ch>` | The controller's WiFi channel (ESP-NOW only): sent once linked and every 5 s; a node on another channel moves to it |
| controller → node | `$NET,<bssid>,<ssid>` | The network the controller is on (ESP-NOW only): its router's access point, or its own hotspot. BSSID 6 B and SSID 1–32 B, both upper-case hex. Sent on change and every 30 s |

Why `CHN`: ESP-NOW only hears its own channel, but part of the traffic on an adjacent channel leaks
through. A node parked on 8 while the controller is on 9 still completes the handshake and then
works intermittently — and a node that only re-searches after several unanswered sends never
does, because an occasional send gets through. The controller saying where it is removes the
guesswork. It is an ordinary message, so on ESP-NOW it carries the authentication tag.

Why `NET` (2026-10-26): `CHN` only helps once linked. After a drop or a reboot the node used to try
channel after channel and wait for a handshake on each. With the network remembered it scans once
(~2 s), finds that access point's channel and goes straight there — the approach the common
ESP-NOW + WiFi tutorials use. BSSID first, because a mesh network's access points share one SSID
on different channels; SSID (strongest) as the fallback. Hopping stays as the fallback when the
network is not in range.

`PWR` units: `<vac>` 0.1 V, `<pmax>` W of DC output, `<ilim>` 0.1 A on the AC side, 0 = unknown.
`<src>` says where `<ilim>` comes from: 0 unknown, 1 a wall outlet (the user's setting on the
node), 2 an AC charging station (J1772 / Type-2 pilot — reserved for a node that reads it).
The node works `<pmax>` out itself — it knows its module's derating and its AC source — so a
controller only has to keep `current × voltage` under it, without knowing the node's model.

Example: `$ST,7,4820,1050,3,07*2735` — 48.20 V, 10.50 A, constant-current, voltage and
current valid, output on.

A node is described by what it declares in `CAP`, not by brand: a controllable rectifier
(reports and accepts V/I) or a measurement-only node for power supplies with no digital
interface (reports V/I, accepts nothing). Field meanings and bit definitions are in
[`include/psu_link/psu_link.h`](include/psu_link/psu_link.h).

## Planned: updating a node's firmware through the controller (not implemented)

Decided 2026-10-27, nothing written yet. The controller downloads a node's firmware and passes it down
the link it already has, so a node needs no network of its own. Same messages over UART and ESP-NOW;
on ESP-NOW each one carries the authentication tag like every other line.

- A node that can be updated says so in `CAP` (a new capability bit). Draft messages: `FWB` (begin:
  size, SHA-256, image name, version) → `FWD,<offset>,<hex data>` chunks, each answered by `FWA,<offset>,
  <result>` → `FWE` (the node checks the SHA-256 and that the image is its own, then switches) /
  `FWX` (abort). Offsets make it resumable after a dropped link.
- **A power node keeps its output on throughout** — the controller may be running from it, so turning
  the output off (or letting it drop) would cut the controller mid-update. The node writes flash while
  it keeps regulating, reboots into the new image and takes over the running output without switching
  it off (a node that finds its supply already running at boot adopts it).
- The controller only starts an update while it is not charging, and shows progress the same way as its
  own update.
- Interrupted or bad image → the node keeps running its current firmware. A node with two image slots
  gets that for free; a small MCU with a single image keeps a resident bootloader that is never updated
  itself, so a failed transfer can always be retried.

## Planned: the controller switches the node's output (not implemented)

Decided 2026-10-27. Only for a controller with its **own** supply — today the TES usually runs from the
node's output, and switching that off powers the controller down. Default stays as now: the node keeps its
output on and the controller never switches it.

- A node that can be switched declares a new capability bit; draft message `OUT,<seq>,<0|1>` → `ACK`.
- **Charge sequence, like a public DC fast charger:** idle = output off. At the start of a session the
  controller sets voltage (to the vehicle's battery voltage) and a low current, switches the output on,
  waits until the reported voltage is there (with a timeout), and only then closes its output contactor;
  at the end it opens the contactor, then switches the output off. The node's limits come from `CAP` and
  `PWR`, as now.
- **Dead-man on the node:** after an `OUT,0`, if the controller's link goes quiet within a few seconds, the
  node assumes the controller was running from it, switches its output back on and drops out of switched
  mode (and says so). A wrong setting then costs a reboot, not a dead controller that only a button press
  on the node can bring back. The controller keeps the link alive while the output is off.
- A node in switched mode remembers it, so after its own reboot it stays off instead of switching on.

## Pairing and link authentication (ESP-NOW)

UART is a wire; ESP-NOW is radio, where anyone in range can transmit. Two layers
protect it, both in this repository so both ends share one implementation:

**Pairing** (`psu_pair.h`) works like Bluetooth's numeric comparison. The two devices
exchange X25519 public keys, the node commits to its nonce before seeing the
controller's, and both then show the same **6-digit code** on their screens. The user
confirms on both sides only if the numbers match. A device that paired with the wrong
unit, or a man in the middle, shows a different number. The result is a long-term key
(LTK) that each side stores with the peer's MAC.

**Link authentication** (`psu_sess.h`). ESP-NOW's own encryption does not stop forgery:
a device always receives broadcast and unencrypted unicast frames, and the receive
callback cannot tell which it got. So every frame carries a counter and an HMAC under a
per-connection key, derived from the LTK by a three-message handshake whenever either
side (re)starts:

```
$SET,1,6720,*DF76~00000001606E75DCB540A93A
                  └counter ┘└── tag ─────┘
```

A forged, altered, reflected or replayed frame fails; so does anything recorded before
the last handshake. On ESP-NOW, a receiver drops every line without a valid tag except
pairing and handshake messages.

| Message | Direction | Purpose |
|---------|-----------|---------|
| `$PKH,<ver>,<role>,<pk>` | both | X25519 public key (node broadcasts, controller replies) |
| `$PCM,<c>` | node → controller | Commitment to the node's nonce |
| `$PNC,<role>,<n>` | both | Nonce (controller first) |
| `$PCF,<role>,<tag>` | both | User confirmed + key confirmation |
| `$PRJ,<role>,<reason>` | both | Cancel |
| `$SH1` / `$SH2` / `$SH3` | C→N / N→C / C→N | Connection handshake |
| `$SHR` | node → controller | Please handshake again (node rebooted) |

The core stays dependency-free: cryptography comes in through `psu_crypto_t`
(`psu_crypto.h`) — X25519 and HMAC-SHA256. `port/esp_idf/psu_crypto_mbedtls.c`
provides it on ESP-IDF; another platform supplies its own.

## Usage

### ESP-IDF component

```bash
git submodule add https://github.com/a950523a/PSU-Link components/psu_link
```

```cmake
idf_component_register(
    ...
    REQUIRES psu_link
)
```

```c
#include "psu_link/psu_link.h"
```

### STM32 / bare-metal CMake

```cmake
add_subdirectory(psu_link)
target_link_libraries(your_target PRIVATE psu_link)
```

## Tests

Host-side, no ESP-IDF needed (ESP-IDF does not build `test/`):

```bash
gcc -std=c99 -Wall -Wextra -Werror -Iinclude psu_link.c test/test_psu_link.c -o test_psu_link
./test_psu_link

gcc -std=c99 -Wall -Wextra -Werror -Iinclude psu_link.c psu_pair.c psu_sess.c test/test_psu_pair.c -o test_psu_pair
./test_psu_pair
```

`test_psu_pair` runs both ends over a simulated radio with random loss (0 / 30 / 50 %),
plus the attacks: forged, altered, reflected and replayed frames, a node that changes
its nonce after committing, a man in the middle, a second node pairing nearby, reboots
on either side, and a lost handshake message. Its SHA-256 / HMAC are a real reference
implementation checked against FIPS 180-2 and RFC 4231; its X25519 is a commutative
stand-in with **no security at all** — enough to test the protocol, not the cryptography,
which mbedTLS provides on the device.

## License

CC BY-NC-SA 4.0
