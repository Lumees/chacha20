# =============================================================================
# Copyright (c) 2026 Lumees Lab / Hasan Kurşun
# SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
#
# Free for non-commercial use (academic, research, hobby, education).
# Commercial use requires a Lumees Lab license: info@lumeeslab.com
# =============================================================================
"""
ChaCha20 IP — Directed cocotb tests for chacha20_top
=====================================================
Tests ChaCha20 per RFC 8439 with official test vectors.
"""

import os
import sys
import struct
import cocotb
from cocotb.clock import Clock
from cocotb.triggers import RisingEdge, ClockCycles

# Add model to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../model'))
from chacha20_model import ChaCha20Model


async def reset_dut(dut):
    dut.rst_n.value = 0
    dut.start_i.value = 0
    dut.next_i.value = 0
    dut.key_i.value = 0
    dut.nonce_i.value = 0
    dut.ctr_i.value = 0
    await ClockCycles(dut.clk, 5)
    dut.rst_n.value = 1
    await ClockCycles(dut.clk, 2)


def key_bytes_to_int(key: bytes) -> int:
    """Convert 32-byte key to integer for RTL (little-endian word packing)."""
    words = struct.unpack('<8I', key)
    val = 0
    for i in range(7, -1, -1):
        val = (val << 32) | words[i]
    return val


def nonce_bytes_to_int(nonce: bytes) -> int:
    """Convert 12-byte nonce to integer for RTL."""
    words = struct.unpack('<3I', nonce)
    val = 0
    for i in range(2, -1, -1):
        val = (val << 32) | words[i]
    return val


async def generate_keystream(dut, key: bytes, nonce: bytes, counter: int):
    """Init and generate one keystream block."""
    key_int = key_bytes_to_int(key)
    nonce_int = nonce_bytes_to_int(nonce)

    dut.key_i.value = key_int
    dut.nonce_i.value = nonce_int
    dut.ctr_i.value = counter

    dut.start_i.value = 1
    await RisingEdge(dut.clk)
    dut.start_i.value = 0

    # Wait for done
    for _ in range(200):
        await RisingEdge(dut.clk)
        if dut.done_o.value == 1:
            break
    else:
        raise TimeoutError("ChaCha20 timeout")

    return int(dut.keystream_o.value)


async def generate_next_block(dut):
    """Generate next keystream block (counter auto-increments)."""
    dut.next_i.value = 1
    await RisingEdge(dut.clk)
    dut.next_i.value = 0

    for _ in range(200):
        await RisingEdge(dut.clk)
        if dut.done_o.value == 1:
            break
    else:
        raise TimeoutError("ChaCha20 next block timeout")

    return int(dut.keystream_o.value)


def ks_int_to_words(ks_int: int) -> list:
    """Convert keystream integer to list of 16 words."""
    words = []
    for i in range(16):
        words.append(ks_int & 0xFFFFFFFF)
        ks_int >>= 32
    return words


# ── Tests ────────────────────────────────────────────────────────────────────

@cocotb.test()
async def test_t01_version(dut):
    """T01: Version register == 0x00010000."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    ver = int(dut.version_o.value)
    dut._log.info(f"[T01] VERSION = 0x{ver:08X}")
    assert ver == 0x00010000, f"VERSION mismatch: 0x{ver:08X}"


@cocotb.test()
async def test_t02_rfc8439_section242(dut):
    """T02: RFC 8439 Section 2.4.2 test vector."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    counter = 1

    expected_words = ChaCha20Model.block_words(key, nonce, counter)
    ks_int = await generate_keystream(dut, key, nonce, counter)
    got_words = ks_int_to_words(ks_int)

    dut._log.info(f"[T02] First word: 0x{got_words[0]:08X} (expected 0x{expected_words[0]:08X})")
    for i in range(16):
        assert got_words[i] == expected_words[i], \
            f"Word [{i}] mismatch: 0x{got_words[i]:08X} != 0x{expected_words[i]:08X}"


@cocotb.test()
async def test_t03_zero_key(dut):
    """T03: All-zero key/nonce/counter."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    key = bytes(32)
    nonce = bytes(12)
    counter = 0

    expected_words = ChaCha20Model.block_words(key, nonce, counter)
    ks_int = await generate_keystream(dut, key, nonce, counter)
    got_words = ks_int_to_words(ks_int)

    dut._log.info(f"[T03] First word: 0x{got_words[0]:08X} (expected 0x{expected_words[0]:08X})")
    for i in range(16):
        assert got_words[i] == expected_words[i], \
            f"Word [{i}] mismatch: 0x{got_words[i]:08X} != 0x{expected_words[i]:08X}"


@cocotb.test()
async def test_t04_next_block(dut):
    """T04: Two consecutive blocks (counter auto-increment)."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    key = bytes(range(32))
    nonce = bytes(12)
    counter = 0

    # First block
    expected_0 = ChaCha20Model.block_words(key, nonce, 0)
    ks_int_0 = await generate_keystream(dut, key, nonce, counter)
    got_0 = ks_int_to_words(ks_int_0)

    for i in range(16):
        assert got_0[i] == expected_0[i], \
            f"Block 0 word [{i}] mismatch: 0x{got_0[i]:08X} != 0x{expected_0[i]:08X}"

    # Second block (next)
    expected_1 = ChaCha20Model.block_words(key, nonce, 1)
    ks_int_1 = await generate_next_block(dut)
    got_1 = ks_int_to_words(ks_int_1)

    dut._log.info(f"[T04] Block 1 first word: 0x{got_1[0]:08X} (expected 0x{expected_1[0]:08X})")
    for i in range(16):
        assert got_1[i] == expected_1[i], \
            f"Block 1 word [{i}] mismatch: 0x{got_1[i]:08X} != 0x{expected_1[i]:08X}"


@cocotb.test()
async def test_t05_back_to_back(dut):
    """T05: Back-to-back independent computations."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    key1 = bytes(range(32))
    nonce1 = bytes(12)
    expected1 = ChaCha20Model.block_words(key1, nonce1, 0)
    ks1 = await generate_keystream(dut, key1, nonce1, 0)
    got1 = ks_int_to_words(ks1)

    await ClockCycles(dut.clk, 2)

    key2 = bytes(32)
    nonce2 = bytes(12)
    expected2 = ChaCha20Model.block_words(key2, nonce2, 0)
    ks2 = await generate_keystream(dut, key2, nonce2, 0)
    got2 = ks_int_to_words(ks2)

    for i in range(16):
        assert got1[i] == expected1[i], f"First block word [{i}] mismatch"
        assert got2[i] == expected2[i], f"Second block word [{i}] mismatch"


@cocotb.test()
async def test_t06_nonzero_counter(dut):
    """T06: Non-zero initial counter."""
    cocotb.start_soon(Clock(dut.clk, 10, units="ns").start())
    await reset_dut(dut)

    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    counter = 42

    expected = ChaCha20Model.block_words(key, nonce, counter)
    ks_int = await generate_keystream(dut, key, nonce, counter)
    got = ks_int_to_words(ks_int)

    for i in range(16):
        assert got[i] == expected[i], \
            f"Word [{i}] mismatch: 0x{got[i]:08X} != 0x{expected[i]:08X}"
