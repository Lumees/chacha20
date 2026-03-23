#!/usr/bin/env python3
# =============================================================================
# Copyright (c) 2026 Lumees Lab / Hasan Kurşun
# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
#
# Free for non-commercial use (academic, research, hobby, education).
# Commercial use requires a Lumees Lab license: info@lumeeslab.com
# =============================================================================
"""
ChaCha20 Golden Model — Lumees Lab
====================================
Bit-accurate ChaCha20 reference implementation (RFC 8439).
No external dependencies — pure Python for RTL verification.

Usage:
    m = ChaCha20Model()
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    ks = m.block(key, nonce, counter=1)
"""

from __future__ import annotations
import struct


class ChaCha20Model:
    """Pure-Python ChaCha20 stream cipher (RFC 8439)."""

    MASK32 = 0xFFFFFFFF

    # "expand 32-byte k"
    SIGMA = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]

    @staticmethod
    def _rotl32(x: int, n: int) -> int:
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    @classmethod
    def _quarter_round(cls, a: int, b: int, c: int, d: int):
        """RFC 8439 Section 2.1 quarter round."""
        a = (a + b) & cls.MASK32; d = d ^ a; d = cls._rotl32(d, 16)
        c = (c + d) & cls.MASK32; b = b ^ c; b = cls._rotl32(b, 12)
        a = (a + b) & cls.MASK32; d = d ^ a; d = cls._rotl32(d,  8)
        c = (c + d) & cls.MASK32; b = b ^ c; b = cls._rotl32(b,  7)
        return a, b, c, d

    @classmethod
    def _double_round(cls, s: list[int]) -> list[int]:
        """Column round + diagonal round."""
        x = list(s)
        # Column rounds
        x[0], x[4], x[8],  x[12] = cls._quarter_round(x[0], x[4], x[8],  x[12])
        x[1], x[5], x[9],  x[13] = cls._quarter_round(x[1], x[5], x[9],  x[13])
        x[2], x[6], x[10], x[14] = cls._quarter_round(x[2], x[6], x[10], x[14])
        x[3], x[7], x[11], x[15] = cls._quarter_round(x[3], x[7], x[11], x[15])
        # Diagonal rounds
        x[0], x[5], x[10], x[15] = cls._quarter_round(x[0], x[5], x[10], x[15])
        x[1], x[6], x[11], x[12] = cls._quarter_round(x[1], x[6], x[11], x[12])
        x[2], x[7], x[8],  x[13] = cls._quarter_round(x[2], x[7], x[8],  x[13])
        x[3], x[4], x[9],  x[14] = cls._quarter_round(x[3], x[4], x[9],  x[14])
        return x

    @classmethod
    def _init_state(cls, key: bytes, nonce: bytes, counter: int) -> list[int]:
        """Initialize 4x4 state matrix."""
        assert len(key) == 32
        assert len(nonce) == 12
        s = list(cls.SIGMA)
        s.extend(struct.unpack('<8I', key))
        s.append(counter & cls.MASK32)
        s.extend(struct.unpack('<3I', nonce))
        return s

    @classmethod
    def block(cls, key: bytes, nonce: bytes, counter: int = 0) -> bytes:
        """Generate one 64-byte keystream block."""
        init = cls._init_state(key, nonce, counter)
        working = list(init)

        # 20 rounds = 10 double-rounds
        for _ in range(10):
            working = cls._double_round(working)

        # Final addition
        result = [(working[i] + init[i]) & cls.MASK32 for i in range(16)]

        return struct.pack('<16I', *result)

    @classmethod
    def block_int(cls, key: bytes, nonce: bytes, counter: int = 0) -> int:
        """Generate keystream block as 512-bit integer (little-endian words)."""
        b = cls.block(key, nonce, counter)
        val = 0
        for i in range(15, -1, -1):
            word = struct.unpack('<I', b[i*4:i*4+4])[0]
            val = (val << 32) | word
        return val

    @classmethod
    def block_words(cls, key: bytes, nonce: bytes, counter: int = 0) -> list[int]:
        """Generate keystream block as list of 16 x 32-bit words."""
        b = cls.block(key, nonce, counter)
        return list(struct.unpack('<16I', b))

    @classmethod
    def encrypt(cls, key: bytes, nonce: bytes, counter: int,
                plaintext: bytes) -> bytes:
        """Encrypt/decrypt plaintext using ChaCha20."""
        result = bytearray()
        for blk_idx in range(0, len(plaintext), 64):
            ks = cls.block(key, nonce, counter + blk_idx // 64)
            chunk = plaintext[blk_idx:blk_idx + 64]
            for i in range(len(chunk)):
                result.append(chunk[i] ^ ks[i])
        return bytes(result)


# ── Test Vectors (RFC 8439) ──────────────────────────────────────────────────

def _self_test():
    m = ChaCha20Model

    passed = 0

    # RFC 8439 Section 2.4.2 test vector
    key = bytes(range(32))  # 00 01 02 ... 1f
    nonce = bytes.fromhex("000000000000004a00000000")
    counter = 1

    ks = m.block(key, nonce, counter)
    words = struct.unpack('<16I', ks)

    # Expected first word: 0xe4e7f110 (from RFC 8439 Section 2.4.2)
    expected_first_word = 0xe4e7f110
    ok = words[0] == expected_first_word
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] RFC 8439 2.4.2 first word = 0x{words[0]:08x} (expected 0x{expected_first_word:08x})")
    if ok:
        passed += 1

    # Check a few more words from the test vector
    expected_words_4 = [
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2,
    ]
    ok = list(words) == expected_words_4
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] RFC 8439 2.4.2 full block match")
    if not ok:
        for i in range(16):
            marker = " <--" if words[i] != expected_words_4[i] else ""
            print(f"         [{i:2d}] got=0x{words[i]:08x} exp=0x{expected_words_4[i]:08x}{marker}")
    if ok:
        passed += 1

    # Test counter=0 block (RFC 8439 Section 2.3.2)
    key_zero = bytes(32)  # all zeros
    nonce_zero = bytes(12)
    ks0 = m.block(key_zero, nonce_zero, 0)
    words0 = struct.unpack('<16I', ks0)
    # With all-zero key/nonce/counter, expected first word = 0xade0b876
    expected_zero_first = 0xade0b876
    ok = words0[0] == expected_zero_first
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] Zero key/nonce/ctr first word = 0x{words0[0]:08x} (expected 0x{expected_zero_first:08x})")
    if ok:
        passed += 1

    # Encrypt / decrypt round-trip
    key_enc = bytes(range(32))
    nonce_enc = bytes(12)
    plaintext = b"Hello, ChaCha20 stream cipher!"
    ct = m.encrypt(key_enc, nonce_enc, 1, plaintext)
    pt_back = m.encrypt(key_enc, nonce_enc, 1, ct)
    ok = pt_back == plaintext
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] Encrypt/decrypt round-trip")
    if ok:
        passed += 1

    total = 4
    print(f"\n  {passed}/{total} self-tests passed")
    return passed == total


if __name__ == "__main__":
    print("ChaCha20 Model Self-Test")
    print("=" * 50)
    ok = _self_test()
    exit(0 if ok else 1)
