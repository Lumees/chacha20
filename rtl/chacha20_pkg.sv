// =============================================================================
// Copyright (c) 2026 Lumees Lab / Hasan Kurşun
// SPDX-License-Identifier: Apache-2.0 WITH Commons-Clause
//
// Licensed under the Apache License 2.0 with Commons Clause restriction.
// You may use this file freely for non-commercial purposes (academic,
// research, hobby, education, personal projects).
//
// COMMERCIAL USE requires a separate license from Lumees Lab.
// Contact: info@lumeeslab.com · https://lumeeslab.com
// =============================================================================
// ChaCha20 IP — Package: constants, types, quarter-round function (RFC 8439)
// =============================================================================

`timescale 1ns/1ps

package chacha20_pkg;

  localparam int IP_VERSION = 32'h0001_0000;

  // ── ChaCha20 parameters ────────────────────────────────────────────────────
  localparam int KEY_W        = 256;   // 256-bit key
  localparam int NONCE_W      = 96;    // 96-bit nonce
  localparam int CTR_W        = 32;    // 32-bit block counter
  localparam int STATE_W      = 512;   // 4x4 x 32 = 512-bit state
  localparam int BLOCK_W      = 512;   // 512-bit keystream block
  localparam int NUM_ROUNDS   = 20;    // 20 rounds (10 double-rounds)
  localparam int NUM_DBLRNDS  = 10;    // 10 double-rounds

  // ── ChaCha20 "expand 32-byte k" constants ─────────────────────────────────
  localparam logic [31:0] SIGMA0 = 32'h61707865;  // "expa"
  localparam logic [31:0] SIGMA1 = 32'h3320646e;  // "nd 3"
  localparam logic [31:0] SIGMA2 = 32'h79622d32;  // "2-by"
  localparam logic [31:0] SIGMA3 = 32'h6b206574;  // "te k"

  // ── 32-bit left-rotate ─────────────────────────────────────────────────────
  function automatic logic [31:0] rotl32(input logic [31:0] x, input int n);
    return (x << n) | (x >> (32 - n));
  endfunction

  // ── Quarter round (RFC 8439 Section 2.1) ───────────────────────────────────
  // a += b; d ^= a; d <<<= 16;
  // c += d; b ^= c; b <<<= 12;
  // a += b; d ^= a; d <<<=  8;
  // c += d; b ^= c; b <<<=  7;
  function automatic void quarter_round(
    input  logic [31:0] a_in,  b_in,  c_in,  d_in,
    output logic [31:0] a_out, b_out, c_out, d_out
  );
    logic [31:0] a, b, c, d;
    a = a_in; b = b_in; c = c_in; d = d_in;

    a = a + b; d = d ^ a; d = rotl32(d, 16);
    c = c + d; b = b ^ c; b = rotl32(b, 12);
    a = a + b; d = d ^ a; d = rotl32(d,  8);
    c = c + d; b = b ^ c; b = rotl32(b,  7);

    a_out = a; b_out = b; c_out = c; d_out = d;
  endfunction

  // ── Column round: QR on columns (0,4,8,12), (1,5,9,13), etc. ─────────────
  function automatic void column_round(
    input  logic [31:0] s_in  [0:15],
    output logic [31:0] s_out [0:15]
  );
    // Copy unchanged initially
    for (int i = 0; i < 16; i++) s_out[i] = s_in[i];

    quarter_round(s_in[ 0], s_in[ 4], s_in[ 8], s_in[12],
                  s_out[ 0], s_out[ 4], s_out[ 8], s_out[12]);
    quarter_round(s_in[ 1], s_in[ 5], s_in[ 9], s_in[13],
                  s_out[ 1], s_out[ 5], s_out[ 9], s_out[13]);
    quarter_round(s_in[ 2], s_in[ 6], s_in[10], s_in[14],
                  s_out[ 2], s_out[ 6], s_out[10], s_out[14]);
    quarter_round(s_in[ 3], s_in[ 7], s_in[11], s_in[15],
                  s_out[ 3], s_out[ 7], s_out[11], s_out[15]);
  endfunction

  // ── Diagonal round: QR on diagonals (0,5,10,15), (1,6,11,12), etc. ───────
  function automatic void diagonal_round(
    input  logic [31:0] s_in  [0:15],
    output logic [31:0] s_out [0:15]
  );
    for (int i = 0; i < 16; i++) s_out[i] = s_in[i];

    quarter_round(s_in[ 0], s_in[ 5], s_in[10], s_in[15],
                  s_out[ 0], s_out[ 5], s_out[10], s_out[15]);
    quarter_round(s_in[ 1], s_in[ 6], s_in[11], s_in[12],
                  s_out[ 1], s_out[ 6], s_out[11], s_out[12]);
    quarter_round(s_in[ 2], s_in[ 7], s_in[ 8], s_in[13],
                  s_out[ 2], s_out[ 7], s_out[ 8], s_out[13]);
    quarter_round(s_in[ 3], s_in[ 4], s_in[ 9], s_in[14],
                  s_out[ 3], s_out[ 4], s_out[ 9], s_out[14]);
  endfunction

  // ── Double round: column round + diagonal round ───────────────────────────
  function automatic void double_round(
    input  logic [31:0] s_in  [0:15],
    output logic [31:0] s_out [0:15]
  );
    logic [31:0] s_mid [0:15];
    column_round  (s_in,  s_mid);
    diagonal_round(s_mid, s_out);
  endfunction

endpackage : chacha20_pkg
