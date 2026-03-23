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
// ChaCha20 IP — Top-level with start/busy/done flow control
// =============================================================================
// FSM: S_IDLE -> S_WAIT -> S_DONE -> S_IDLE
//
// Software flow:
//   1. Load key, nonce, counter
//   2. Assert start_i to init and generate first keystream block
//   3. Wait for done_o pulse
//   4. Read keystream_o (512-bit keystream), XOR with plaintext
//   5. Assert next_i to generate next block (counter auto-increments)
// =============================================================================

`timescale 1ns/1ps

import chacha20_pkg::*;

module chacha20_top (
  input  logic              clk,
  input  logic              rst_n,

  // Control
  input  logic              start_i,       // pulse: init + generate first block
  input  logic              next_i,        // pulse: generate next block
  output logic              busy_o,
  output logic              done_o,

  // Key, nonce, counter
  input  logic [KEY_W-1:0]   key_i,
  input  logic [NONCE_W-1:0] nonce_i,
  input  logic [CTR_W-1:0]   ctr_i,

  // Result (512-bit keystream block)
  output logic [BLOCK_W-1:0] keystream_o,

  // Info
  output logic [31:0]       version_o
);

  assign version_o = IP_VERSION;

  // ── Core signals ──────────────────────────────────────────────────────────
  logic            core_init;
  logic            core_next;
  logic [BLOCK_W-1:0] core_keystream;
  logic            core_ready;
  logic            core_valid;

  chacha20_core u_core (
    .clk         (clk),
    .rst_n       (rst_n),
    .init        (core_init),
    .next        (core_next),
    .key_i       (key_i),
    .nonce_i     (nonce_i),
    .ctr_i       (ctr_i),
    .keystream_o (core_keystream),
    .ready_o     (core_ready),
    .valid_o     (core_valid)
  );

  // ── State machine ─────────────────────────────────────────────────────────
  typedef enum logic [1:0] {S_IDLE, S_WAIT, S_DONE} state_t;
  state_t state;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      state       <= S_IDLE;
      busy_o      <= 1'b0;
      done_o      <= 1'b0;
      keystream_o <= '0;
      core_init   <= 1'b0;
      core_next   <= 1'b0;
    end else begin
      // Default: deassert pulses
      core_init <= 1'b0;
      core_next <= 1'b0;

      unique case (state)

        S_IDLE: begin
          done_o <= 1'b0;
          if (start_i) begin
            core_init <= 1'b1;
            busy_o    <= 1'b1;
            state     <= S_WAIT;
          end else if (next_i) begin
            core_next <= 1'b1;
            busy_o    <= 1'b1;
            state     <= S_WAIT;
          end
        end

        S_WAIT: begin
          if (core_valid) begin
            keystream_o <= core_keystream;
            state       <= S_DONE;
          end
        end

        S_DONE: begin
          done_o <= 1'b1;
          busy_o <= 1'b0;
          state  <= S_IDLE;
        end

      endcase
    end
  end

endmodule : chacha20_top
