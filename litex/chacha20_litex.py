# =============================================================================
# Copyright (c) 2026 Lumees Lab / Hasan Kurşun
# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
#
# Free for non-commercial use (academic, research, hobby, education).
# Commercial use requires a Lumees Lab license: info@lumeeslab.com
# =============================================================================
"""
ChaCha20 LiteX Module
======================
Directly instantiates chacha20_top.sv and wires it to LiteX CSR registers.

CSR registers:
  ctrl         [0]=start(self-clearing) [1]=next(self-clearing)
               [2]=busy(RO) [3]=done(RO)
  key_0..key_7     256-bit key (8 x 32-bit words)
  nonce_0..nonce_2 96-bit nonce (3 x 32-bit words)
  counter          32-bit block counter
  keystream_0..keystream_15  512-bit keystream (16 x 32-bit, RO)
  status       [0]=ready [1]=done [2]=busy (RO)
  info         [7:0]=key_bytes [15:8]=nonce_bytes (RO)
  version      IP version (RO)
"""

from migen import *
from litex.soc.interconnect.csr import *

import os

CHACHA20_RTL_DIR = os.path.join(os.path.dirname(__file__), '../rtl')


class ChaCha20(Module, AutoCSR):
    def __init__(self, platform):
        # ── Platform sources ─────────────────────────────────────────────
        for f in ['chacha20_pkg.sv', 'chacha20_core.sv', 'chacha20_top.sv']:
            platform.add_source(os.path.join(CHACHA20_RTL_DIR, f))

        # ── CSR registers (RW) ───────────────────────────────────────────
        self.ctrl = CSRStorage(8, name="ctrl",
                               description="[0]=start [1]=next (self-clear)")

        # 8 key words
        self._key = []
        for i in range(8):
            csr = CSRStorage(32, name=f"key_{i}",
                             description=f"Key word {i}")
            setattr(self, f"key_{i}", csr)
            self._key.append(csr)

        # 3 nonce words
        self._nonce = []
        for i in range(3):
            csr = CSRStorage(32, name=f"nonce_{i}",
                             description=f"Nonce word {i}")
            setattr(self, f"nonce_{i}", csr)
            self._nonce.append(csr)

        # Counter
        self.counter = CSRStorage(32, name="counter",
                                  description="Block counter")

        # ── CSR registers (RO) ───────────────────────────────────────────
        self._keystream = []
        for i in range(16):
            csr = CSRStatus(32, name=f"keystream_{i}",
                            description=f"Keystream word {i}")
            setattr(self, f"keystream_{i}", csr)
            self._keystream.append(csr)

        self.status  = CSRStatus(8,  name="status",
                                 description="[0]=ready [1]=done [2]=busy")
        self.info    = CSRStatus(32, name="info",
                                 description="[7:0]=32 [15:8]=12")
        self.version = CSRStatus(32, name="version", description="IP version")

        # Constant outputs
        self.comb += self.info.status.eq((12 << 8) | 32)

        # ── Core signals ─────────────────────────────────────────────────
        start_pulse = Signal()
        next_pulse  = Signal()
        busy_sig    = Signal()
        done_sig    = Signal()
        keystream_result = Signal(512)
        version_sig = Signal(32)

        # Build 256-bit key from CSR storage
        key_sig = Signal(256)
        for i in range(8):
            self.comb += key_sig[i*32 : i*32 + 32].eq(
                self._key[i].storage)

        # Build 96-bit nonce from CSR storage
        nonce_sig = Signal(96)
        for i in range(3):
            self.comb += nonce_sig[i*32 : i*32 + 32].eq(
                self._nonce[i].storage)

        # Counter
        ctr_sig = Signal(32)
        self.comb += ctr_sig.eq(self.counter.storage)

        # Start/next pulse
        self.comb += [
            start_pulse.eq(self.ctrl.re & self.ctrl.storage[0]),
            next_pulse.eq(self.ctrl.re & self.ctrl.storage[1]),
        ]

        # Status — latch done
        done_latched = Signal(reset=0)
        self.sync += [
            If(start_pulse | next_pulse,
                done_latched.eq(0),
            ).Elif(done_sig,
                done_latched.eq(1),
            )
        ]
        self.comb += [
            self.status.status[0].eq(~busy_sig),
            self.status.status[1].eq(done_latched),
            self.status.status[2].eq(busy_sig),
        ]

        # Latch keystream result
        ks_latched = Signal(512)
        self.sync += If(done_sig, ks_latched.eq(keystream_result))
        for i in range(16):
            self.comb += self._keystream[i].status.eq(
                ks_latched[i*32 : i*32 + 32])

        # IRQ on done
        self.irq = Signal()
        done_prev = Signal()
        self.sync += done_prev.eq(done_sig)
        self.comb += self.irq.eq(done_sig & ~done_prev)

        # ── Zero tie-off for unused signals ──────────────────────────────
        zero_pad = Signal()
        self.comb += zero_pad.eq(0)

        # ── ChaCha20 top instance ────────────────────────────────────────
        self.specials += Instance("chacha20_top",
            i_clk         = ClockSignal(),
            i_rst_n       = ~ResetSignal(),
            i_start_i     = start_pulse,
            i_next_i      = next_pulse,
            o_busy_o      = busy_sig,
            o_done_o      = done_sig,
            i_key_i       = key_sig,
            i_nonce_i     = nonce_sig,
            i_ctr_i       = ctr_sig,
            o_keystream_o = keystream_result,
            o_version_o   = version_sig,
        )

        self.comb += self.version.status.eq(version_sig)
