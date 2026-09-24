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

Example: `$ST,7,4820,1050,3,07*2735` — 48.20 V, 10.50 A, constant-current, voltage and
current valid, output on.

A node is described by what it declares in `CAP`, not by brand: a controllable rectifier
(reports and accepts V/I) or a measurement-only node for power supplies with no digital
interface (reports V/I, accepts nothing). Field meanings and bit definitions are in
[`include/psu_link/psu_link.h`](include/psu_link/psu_link.h).

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
```

## License

CC BY-NC-SA 4.0
