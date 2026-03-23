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
// ChaCha20 IP — Core: 20-round ChaCha20 stream cipher engine (RFC 8439)
// =============================================================================
// Iterative ChaCha20 engine processing one half-round (column or diagonal)
// per clock cycle (20 cycles per 512-bit keystream block).
//
// State matrix layout (4x4 x 32-bit words):
//   [0]  [1]  [2]  [3]   <- constants "expand 32-byte k"
//   [4]  [5]  [6]  [7]   <- key[0..3]
//   [8]  [9]  [10] [11]  <- key[4..7]
//   [12] [13] [14] [15]  <- counter, nonce[0..2]
//
// Protocol:
//   - Assert init=1 to load key, nonce, counter into initial state
//   - Assert next=1 to generate keystream for next block (auto-increments counter)
//   - Wait for valid_o pulse; read keystream_o (512 bits)
//   - ready_o is high when idle
// =============================================================================

`timescale 1ns/1ps

import chacha20_pkg::*;

module chacha20_core (
  input  logic          clk,
  input  logic          rst_n,

  // Control
  input  logic          init,           // pulse: load key/nonce/counter
  input  logic          next,           // pulse: generate next keystream block
  input  logic [KEY_W-1:0]   key_i,    // 256-bit key
  input  logic [NONCE_W-1:0] nonce_i,  // 96-bit nonce
  input  logic [CTR_W-1:0]   ctr_i,    // 32-bit initial counter

  // Output
  output logic [BLOCK_W-1:0] keystream_o,  // 512-bit keystream block
  output logic          ready_o,        // high when idle
  output logic          valid_o         // pulses one cycle when block is ready
);

  // ── State machine ─────────────────────────────────────────────────────────
  typedef enum logic [1:0] {S_IDLE, S_ROUND, S_DONE} state_t;
  state_t state;

  // ── Round counter ─────────────────────────────────────────────────────────
  logic [4:0] half_rnd_cnt;  // 0..19 (20 half-rounds: col/diag alternating)
  logic       col_not_diag;  // 1 = column round, 0 = diagonal round

  // ── Working state ─────────────────────────────────────────────────────────
  logic [31:0] ws [0:15];

  // ── Initial state (saved for final addition) ──────────────────────────────
  logic [31:0] init_state [0:15];

  // ── Block counter (auto-increments) ───────────────────────────────────────
  logic [31:0] block_ctr;

  // ── Combinational half-round output (column OR diagonal) ─────────────────
  logic [31:0] hr_out [0:15];

  always_comb begin
    if (col_not_diag)
      column_round  (ws, hr_out);
    else
      diagonal_round(ws, hr_out);
  end

  // ── Sequential logic ─────────────────────────────────────────────────────
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state        <= S_IDLE;
      half_rnd_cnt <= '0;
      col_not_diag <= 1'b1;
      valid_o      <= 1'b0;
      keystream_o  <= '0;
      block_ctr    <= '0;
      for (int i = 0; i < 16; i++) begin
        ws[i]         <= '0;
        init_state[i] <= '0;
      end
    end else begin
      valid_o <= 1'b0;

      unique case (state)

        S_IDLE: begin
          if (init) begin
            // Setup initial state from key, nonce, counter
            // Constants
            init_state[0]  <= SIGMA0;
            init_state[1]  <= SIGMA1;
            init_state[2]  <= SIGMA2;
            init_state[3]  <= SIGMA3;
            // Key (little-endian word order: key[31:0] -> state[4])
            init_state[4]  <= key_i[31:0];
            init_state[5]  <= key_i[63:32];
            init_state[6]  <= key_i[95:64];
            init_state[7]  <= key_i[127:96];
            init_state[8]  <= key_i[159:128];
            init_state[9]  <= key_i[191:160];
            init_state[10] <= key_i[223:192];
            init_state[11] <= key_i[255:224];
            // Counter
            init_state[12] <= ctr_i;
            // Nonce (little-endian word order)
            init_state[13] <= nonce_i[31:0];
            init_state[14] <= nonce_i[63:32];
            init_state[15] <= nonce_i[95:64];

            block_ctr <= ctr_i;

            // Also load into working state for immediate first block
            ws[0]  <= SIGMA0;
            ws[1]  <= SIGMA1;
            ws[2]  <= SIGMA2;
            ws[3]  <= SIGMA3;
            ws[4]  <= key_i[31:0];
            ws[5]  <= key_i[63:32];
            ws[6]  <= key_i[95:64];
            ws[7]  <= key_i[127:96];
            ws[8]  <= key_i[159:128];
            ws[9]  <= key_i[191:160];
            ws[10] <= key_i[223:192];
            ws[11] <= key_i[255:224];
            ws[12] <= ctr_i;
            ws[13] <= nonce_i[31:0];
            ws[14] <= nonce_i[63:32];
            ws[15] <= nonce_i[95:64];

            half_rnd_cnt <= '0;
            col_not_diag <= 1'b1;
            state        <= S_ROUND;
          end else if (next) begin
            // Increment counter and start next block
            block_ctr <= block_ctr + 1;

            for (int i = 0; i < 16; i++)
              ws[i] <= init_state[i];
            ws[12] <= block_ctr + 1;
            init_state[12] <= block_ctr + 1;

            half_rnd_cnt <= '0;
            col_not_diag <= 1'b1;
            state        <= S_ROUND;
          end
        end

        S_ROUND: begin
          // Apply one half-round (column or diagonal) per cycle
          for (int i = 0; i < 16; i++)
            ws[i] <= hr_out[i];

          half_rnd_cnt <= half_rnd_cnt + 1;
          col_not_diag <= ~col_not_diag;  // alternate col/diag

          if (half_rnd_cnt == 5'd19) begin
            state <= S_DONE;
          end
        end

        S_DONE: begin
          // Final addition: working_state + initial_state (mod 2^32)
          for (int i = 0; i < 16; i++) begin
            keystream_o[i*32 +: 32] <= ws[i] + init_state[i];
          end

          valid_o <= 1'b1;
          state   <= S_IDLE;
        end

      endcase
    end
  end

  assign ready_o = (state == S_IDLE);

endmodule : chacha20_core
