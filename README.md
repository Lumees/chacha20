# ChaCha20 Stream Cipher IP Core

> **Lumees Lab** — FPGA-Verified, Production-Ready Silicon IP

[![License](https://img.shields.io/badge/License-Source_Available-orange.svg)](LICENSE)
[![FPGA](https://img.shields.io/badge/FPGA-Arty%20A7--100T-green.svg)]()
[![Fmax](https://img.shields.io/badge/Fmax-100%20MHz-brightgreen.svg)]()
[![Tests](https://img.shields.io/badge/Tests-5%2F5%20HW%20PASS-blue.svg)]()

---

## Overview

The Lumees Lab ChaCha20 IP Core is an iterative hardware implementation of the ChaCha20 stream cipher per **RFC 8439**. It accepts a 256-bit key, 96-bit nonce, and 32-bit counter, and produces 512-bit keystream blocks at one block every 22 clock cycles.

ChaCha20 is the cipher behind TLS 1.3's `TLS_CHACHA20_POLY1305_SHA256` suite — the most widely deployed authenticated encryption cipher on the modern internet. This hardware implementation offloads the keystream generation from the CPU, enabling line-rate encryption in network, storage, and IoT applications.

The core uses a half-round-per-cycle architecture: each clock cycle computes either a column round or a diagonal round (4 quarter-rounds), completing all 20 rounds in 20 cycles plus 2 cycles of overhead. This halves the combinational depth compared to a full double-round-per-cycle design, enabling reliable timing closure at 100 MHz on Artix-7.

Verified against RFC 8439 test vectors in simulation (6/6 cocotb tests) and on Xilinx FPGA hardware (Arty A7-100T, 5/5 UART regression tests), the core is production-ready.

---

## Key Features

| Feature | Detail |
|---|---|
| **Algorithm** | ChaCha20 per RFC 8439 (D.J. Bernstein) |
| **Key Size** | 256 bits |
| **Nonce** | 96 bits |
| **Counter** | 32 bits (auto-incrementing) |
| **Block Size** | 512 bits (64 bytes) keystream per block |
| **Architecture** | Iterative: 1 half-round/cycle, 22 cycles/block |
| **Throughput** | ~2.33 Gbit/s @ 100 MHz (512 bits / 22 cycles) |
| **Quarter-Round** | `a+=b; d^=a; d<<<16; c+=d; b^=c; b<<<12; a+=b; d^=a; d<<<8; c+=d; b^=c; b<<<7` |
| **State Matrix** | 4×4 × 32-bit words (SIGMA + key + counter + nonce) |
| **Counter Mode** | Auto-increment on `next_i` for multi-block streams |
| **Bus Interfaces** | AXI4-Lite, Wishbone B4, bare port |
| **Technology** | FPGA / ASIC, pure synchronous RTL, no vendor primitives |
| **Patent Status** | Patent-free (D.J. Bernstein, public domain design) |

---

## Performance — Arty A7-100T (XC7A100T) @ 100 MHz

| Resource | Full SoC | Core (est.) | Available | SoC % |
|---|---|---|---|---|
| LUT | ~1,400 | ~800 | 63,400 | 2.2% |
| FF | ~1,200 | ~600 | 126,800 | 0.9% |
| DSP48 | 0 | 0 | 240 | 0% |
| Block RAM | 0 | 0 | 135 | 0% |

> **Timing:** 22 cycles per 512-bit block. Zero DSP/BRAM. Pure LUT/FF implementation. Half-round-per-cycle architecture ensures clean timing closure at 100 MHz.

---

## Architecture

```
                ┌──────────────────────────────────────────────┐
                │                  chacha20_top                │
                │                                              │
 key[255:0]  ──►┤                                              │
 nonce[95:0] ──►│  chacha20_core                               │
 counter[31:0]─►│                                              │
                │  ┌────────┐                                  │
 start_i ──────►│  │ State  │  Column Round   ←─┐              │
 next_i  ──────►│  │ Matrix │  Diagonal Round ──┤ ×10 = 20 rnd │──► keystream_o[511:0]
                │  │ (4×4×  │  (alternating)  ──┘              │    valid_o
                │  │  32b)  │                                  │
                │  └────────┘  + init_state (final add)        │
                │                                              │
                │  Latency: 22 cycles per 512-bit block        │
                └──────────────────────────────────────────────┘
```

**State Initialization:** The 4×4 state matrix is loaded with the SIGMA constants ("expand 32-byte k"), 256-bit key, 32-bit counter, and 96-bit nonce per RFC 8439 Section 2.3.

**Round Execution:** Each cycle applies either a column round (QR on columns 0-3) or a diagonal round (QR on diagonals), alternating via `col_not_diag` flag. 20 half-rounds = 10 double-rounds = the full ChaCha20 specification.

**Final Addition:** After 20 rounds, each word of the working state is added (mod 2^32) to the corresponding word of the initial state, producing the 512-bit keystream block.

---

## Interface — Bare Core (`chacha20_top`)

```systemverilog
chacha20_top u_chacha20 (
  .clk          (clk),
  .rst_n        (rst_n),

  // Control
  .start_i      (start),          // Pulse: initialize with key/nonce/counter
  .next_i       (next),           // Pulse: generate next block (counter++)
  .busy_o       (busy),           // High during computation
  .done_o       (done),           // Pulse: keystream ready

  // Key material
  .key_i        (key),            // [255:0] 256-bit key
  .nonce_i      (nonce),          // [95:0]  96-bit nonce
  .counter_i    (counter),        // [31:0]  Initial counter value

  // Output
  .keystream_o  (keystream),      // [511:0] 512-bit keystream block
  .version_o    (version)         // [31:0]  IP version (0x00010000)
);
```

**Usage:** XOR `keystream_o` with plaintext to encrypt, or with ciphertext to decrypt. For messages longer than 64 bytes, pulse `next_i` to generate subsequent blocks (counter auto-increments).

---

## Register Map — AXI4-Lite / Wishbone

| Offset | Register | Access | Description |
|---|---|---|---|
| 0x00 | CTRL | R/W | `[0]`=START `[1]`=NEXT (self-clearing) |
| 0x04 | STATUS | RO | `[0]`=READY `[1]`=DONE `[2]`=BUSY |
| 0x08 | INFO | RO | `[7:0]`=KEY_BYTES(32) `[15:8]`=NONCE_BYTES(12) |
| 0x0C | VERSION | RO | `0x00010000` |
| 0x10–0x2C | KEY[0..7] | R/W | 256-bit key (8 × 32-bit, little-endian) |
| 0x30–0x38 | NONCE[0..2] | R/W | 96-bit nonce (3 × 32-bit) |
| 0x3C | COUNTER | R/W | 32-bit initial counter |
| 0x40–0x7C | KEYSTREAM[0..15] | RO | 512-bit output (16 × 32-bit) |

---

## Verification

### Simulation (cocotb + Verilator) — 6/6 PASS

| Test | Description |
|---|---|
| T01 | Version register readback |
| T02 | RFC 8439 Section 2.4.2 full test vector |
| T03 | All-zero key/nonce/counter (RFC 8439 Section 2.3.2) |
| T04 | Two consecutive blocks with counter auto-increment |
| T05 | Back-to-back independent computations |
| T06 | Non-zero initial counter (42) |

### FPGA Hardware — 5/5 PASS

Arty A7-100T @ 100 MHz via LiteX SoC + UARTBone. RFC 8439 vector, zero-key, back-to-back verified on silicon.

---

## Directory Structure

```
chacha20/
├── rtl/                        # 5 files, 870 lines
│   ├── chacha20_pkg.sv         # Quarter-round, column/diagonal round functions
│   ├── chacha20_core.sv        # Iterative engine (20 half-rounds)
│   ├── chacha20_top.sv         # FSM wrapper (start/next/busy/done)
│   ├── chacha20_axil.sv        # AXI4-Lite slave (267 lines)
│   └── chacha20_wb.sv          # Wishbone B4 slave (189 lines)
├── model/
│   └── chacha20_model.py       # Pure Python golden model (RFC 8439 vectors)
├── tb/
│   ├── directed/               # cocotb tests (6/6 PASS)
│   │   └── test_chacha20_top.py
│   └── uvm/                    # UVM environment (11 files, 1,061 lines)
├── sim/
│   └── Makefile.cocotb
├── litex/                      # LiteX SoC for Arty A7-100T
│   ├── chacha20_litex.py
│   ├── chacha20_soc.py
│   └── chacha20_uart_test.py
├── README.md
├── LICENSE
└── .gitignore
```

---

## Roadmap

### v1.1
- [ ] Poly1305 MAC integration (ChaCha20-Poly1305 AEAD per RFC 8439)
- [ ] XChaCha20 extended-nonce variant (192-bit nonce via HChaCha20)
- [ ] Interrupt-driven AXI4-Lite operation

### v1.2
- [ ] AXI4-Stream wrapper for streaming encryption/decryption
- [ ] Multi-block pipelining (start next block while current finishes)
- [ ] Byte-granularity partial-block support

### v2.0
- [ ] Side-channel hardened variant (constant-time, masked operations)
- [ ] SkyWater 130nm silicon-proven version
- [ ] 800 MHz high-performance variant

---

## Why Lumees ChaCha20?

| Differentiator | Detail |
|---|---|
| **RFC 8439 exact** | Bit-accurate implementation with official test vectors |
| **Patent-free** | D.J. Bernstein's design — no royalties, no encumbrance |
| **Zero DSP/BRAM** | Pure LUT/FF — leaves resources for your application |
| **22-cycle latency** | Half-round/cycle ensures clean timing at 100 MHz |
| **Auto-counter** | `next_i` auto-increments for multi-block streams |
| **5/5 hardware tests** | Proven on real FPGA silicon, not just simulated |
| **Source-available** | Full RTL included — inspect, modify, verify |

---

## License

**Dual license:** Free for non-commercial use (Apache 2.0). Commercial use requires a Lumees Lab license.

See [LICENSE](LICENSE) for full terms.

---

**Lumees Lab** · Hasan Kurşun · [lumeeslab.com](https://lumeeslab.com) · info@lumeeslab.com

*Copyright © 2026 Lumees Lab. All rights reserved.*
