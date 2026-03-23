#!/usr/bin/env python3
# =============================================================================
# Copyright (c) 2026 Lumees Lab / Hasan Kurşun
# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
#
# Free for non-commercial use (academic, research, hobby, education).
# Commercial use requires a Lumees Lab license: info@lumeeslab.com
# =============================================================================
"""
ChaCha20 UART Hardware Regression Test
========================================
Runs on Arty A7-100T via litex_server + RemoteClient.
Requires: litex_server --uart --uart-port /dev/ttyUSB1 --uart-baudrate 115200
"""

import os
import sys
import time
import struct

from litex.tools.litex_client import RemoteClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../model'))
from chacha20_model import ChaCha20Model

PASS_COUNT = 0
FAIL_COUNT = 0


class ChaCha20Client:
    def __init__(self, host='localhost', tcp_port=1234, csr_csv=None):
        self.client = RemoteClient(host=host, port=tcp_port, csr_csv=csr_csv)
        self.client.open()

    def close(self):
        self.client.close()

    def _w(self, reg: str, val: int):
        getattr(self.client.regs, f"chacha20_{reg}").write(val & 0xFFFFFFFF)

    def _r(self, reg: str) -> int:
        return int(getattr(self.client.regs, f"chacha20_{reg}").read())

    def write_key(self, key: bytes):
        """Write 32-byte key to 8 key registers."""
        words = struct.unpack('<8I', key)
        for i, w in enumerate(words):
            self._w(f"key_{i}", w)

    def write_nonce(self, nonce: bytes):
        """Write 12-byte nonce to 3 nonce registers."""
        words = struct.unpack('<3I', nonce)
        for i, w in enumerate(words):
            self._w(f"nonce_{i}", w)

    def write_counter(self, ctr: int):
        self._w("counter", ctr)

    def start(self):
        self._w("ctrl", 0x01)

    def next_block(self):
        self._w("ctrl", 0x02)

    def status(self) -> dict:
        s = self._r("status")
        return {"ready": bool(s & 1), "done": bool(s & 2), "busy": bool(s & 4)}

    def wait_done(self, timeout=5.0) -> bool:
        t0 = time.time()
        while time.time() - t0 < timeout:
            if self.status()["done"]:
                return True
            time.sleep(0.001)
        return False

    def read_keystream(self) -> list:
        """Read 512-bit keystream as list of 16 words."""
        words = []
        for i in range(16):
            w = self._r(f"keystream_{i}")
            words.append(w & 0xFFFFFFFF)
        return words

    def version(self) -> int:
        return self._r("version")

    def compute(self, key: bytes, nonce: bytes, counter: int) -> list:
        """Generate one keystream block."""
        self.write_key(key)
        self.write_nonce(nonce)
        self.write_counter(counter)
        time.sleep(0.001)
        self.start()
        time.sleep(0.001)
        if not self.wait_done(timeout=5.0):
            raise TimeoutError("ChaCha20 timeout")
        return self.read_keystream()


def check(name, condition, detail=""):
    global PASS_COUNT, FAIL_COUNT
    if condition:
        print(f"  [PASS] {name}")
        PASS_COUNT += 1
    else:
        print(f"  [FAIL] {name}  {detail}")
        FAIL_COUNT += 1


# ── Tests ────────────────────────────────────────────────────────────────────

def test_version(dut: ChaCha20Client):
    print("\n[T01] Version register")
    ver = dut.version()
    check("VERSION == 0x00010000", ver == 0x00010000, f"got 0x{ver:08X}")


def test_rfc8439(dut: ChaCha20Client):
    print("\n[T02] RFC 8439 Section 2.4.2 test vector")
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    counter = 1

    expected = ChaCha20Model.block_words(key, nonce, counter)
    got = dut.compute(key, nonce, counter)
    match = all(got[i] == expected[i] for i in range(16))
    check("Full block match", match,
          f"first word: got 0x{got[0]:08x} expected 0x{expected[0]:08x}")


def test_zero_key(dut: ChaCha20Client):
    print("\n[T03] All-zero key/nonce/counter")
    key = bytes(32)
    nonce = bytes(12)
    counter = 0

    expected = ChaCha20Model.block_words(key, nonce, counter)
    got = dut.compute(key, nonce, counter)
    match = all(got[i] == expected[i] for i in range(16))
    check("Full block match", match,
          f"first word: got 0x{got[0]:08x} expected 0x{expected[0]:08x}")


def test_back_to_back(dut: ChaCha20Client):
    print("\n[T04] Back-to-back computations")
    key = bytes(range(32))
    nonce = bytes(12)

    expected1 = ChaCha20Model.block_words(key, nonce, 0)
    got1 = dut.compute(key, nonce, 0)

    expected2 = ChaCha20Model.block_words(key, nonce, 1)
    got2 = dut.compute(key, nonce, 1)

    match1 = all(got1[i] == expected1[i] for i in range(16))
    match2 = all(got2[i] == expected2[i] for i in range(16))
    check("First block match", match1)
    check("Second block match", match2)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    csr_csv = os.path.join(os.path.dirname(__file__),
                           'build/digilent_arty/csr.csv')
    if not os.path.exists(csr_csv):
        csr_csv = None

    dut = ChaCha20Client(csr_csv=csr_csv)

    try:
        print("=" * 60)
        print("ChaCha20 UART Hardware Regression")
        print("=" * 60)

        test_version(dut)
        test_rfc8439(dut)
        test_zero_key(dut)
        test_back_to_back(dut)

        print("\n" + "=" * 60)
        total = PASS_COUNT + FAIL_COUNT
        print(f"Result: {PASS_COUNT}/{total} PASS  {FAIL_COUNT}/{total} FAIL")
        print("=" * 60)
        sys.exit(0 if FAIL_COUNT == 0 else 1)

    finally:
        dut.close()


if __name__ == "__main__":
    main()
