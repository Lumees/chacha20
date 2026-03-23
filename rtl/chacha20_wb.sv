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
// ChaCha20 IP — Wishbone B4 Classic Interface Wrapper
// =============================================================================
// Same register map as chacha20_axil.sv.
// =============================================================================

`timescale 1ns/1ps

import chacha20_pkg::*;

module chacha20_wb (
  // Wishbone system
  input  logic        CLK_I,
  input  logic        RST_I,

  // Wishbone slave
  input  logic [31:0] ADR_I,
  input  logic [31:0] DAT_I,
  output logic [31:0] DAT_O,
  input  logic        WE_I,
  input  logic [3:0]  SEL_I,
  input  logic        STB_I,
  input  logic        CYC_I,
  output logic        ACK_O,
  output logic        ERR_O,
  output logic        RTY_O,

  // Interrupt
  output logic        irq
);

  assign ERR_O = 1'b0;
  assign RTY_O = 1'b0;

  // ── Internal registers ────────────────────────────────────────────────────
  logic [31:0] reg_key       [0:7];
  logic [31:0] reg_nonce     [0:2];
  logic [31:0] reg_counter;
  logic [31:0] reg_keystream [0:15];
  logic        reg_busy, reg_done;

  // ── Engine signals ────────────────────────────────────────────────────────
  logic             top_start, top_next;
  logic             top_busy, top_done;
  logic [KEY_W-1:0]   top_key;
  logic [NONCE_W-1:0] top_nonce;
  logic [CTR_W-1:0]   top_ctr;
  logic [BLOCK_W-1:0] top_keystream;
  logic [31:0]       top_version;

  always_comb begin
    for (int i = 0; i < 8; i++)
      top_key[i*32 +: 32] = reg_key[i];
    for (int i = 0; i < 3; i++)
      top_nonce[i*32 +: 32] = reg_nonce[i];
    top_ctr = reg_counter;
  end

  chacha20_top u_chacha20 (
    .clk         (CLK_I),
    .rst_n       (~RST_I),
    .start_i     (top_start),
    .next_i      (top_next),
    .busy_o      (top_busy),
    .done_o      (top_done),
    .key_i       (top_key),
    .nonce_i     (top_nonce),
    .ctr_i       (top_ctr),
    .keystream_o (top_keystream),
    .version_o   (top_version)
  );

  // ── IRQ ───────────────────────────────────────────────────────────────────
  logic done_prev;
  always_ff @(posedge CLK_I) begin
    if (RST_I) done_prev <= 1'b0;
    else       done_prev <= reg_done;
  end
  assign irq = reg_done & ~done_prev;

  // ── Bus logic ─────────────────────────────────────────────────────────────
  always_ff @(posedge CLK_I) begin
    if (RST_I) begin
      ACK_O       <= 1'b0;
      DAT_O       <= '0;
      reg_busy    <= 1'b0;
      reg_done    <= 1'b0;
      top_start   <= 1'b0;
      top_next    <= 1'b0;
      reg_counter <= '0;
      for (int i = 0; i < 8; i++)
        reg_key[i] <= '0;
      for (int i = 0; i < 3; i++)
        reg_nonce[i] <= '0;
      for (int i = 0; i < 16; i++)
        reg_keystream[i] <= '0;
    end else begin
      ACK_O     <= 1'b0;
      top_start <= 1'b0;
      top_next  <= 1'b0;

      reg_busy <= top_busy;
      if (top_done) begin
        reg_done <= 1'b1;
        for (int i = 0; i < 16; i++)
          reg_keystream[i] <= top_keystream[i*32 +: 32];
      end

      if (CYC_I && STB_I && !ACK_O) begin
        ACK_O <= 1'b1;

        if (WE_I) begin
          unique case (ADR_I[9:2])
            8'h00: begin  // CTRL
              if (DAT_I[0] && !reg_busy) begin
                top_start <= 1'b1;
                reg_done  <= 1'b0;
              end
              if (DAT_I[1] && !reg_busy) begin
                top_next <= 1'b1;
                reg_done <= 1'b0;
              end
            end
            8'h04: reg_key[0]    <= DAT_I;
            8'h05: reg_key[1]    <= DAT_I;
            8'h06: reg_key[2]    <= DAT_I;
            8'h07: reg_key[3]    <= DAT_I;
            8'h08: reg_key[4]    <= DAT_I;
            8'h09: reg_key[5]    <= DAT_I;
            8'h0A: reg_key[6]    <= DAT_I;
            8'h0B: reg_key[7]    <= DAT_I;
            8'h0C: reg_nonce[0]  <= DAT_I;
            8'h0D: reg_nonce[1]  <= DAT_I;
            8'h0E: reg_nonce[2]  <= DAT_I;
            8'h0F: reg_counter   <= DAT_I;
            default: ;
          endcase
        end else begin
          unique case (ADR_I[9:2])
            8'h00: DAT_O <= {28'd0, reg_done, reg_busy, 2'b00};
            8'h01: DAT_O <= 32'h0;
            8'h02: DAT_O <= {16'h0, 8'd12, 8'd32};
            8'h03: DAT_O <= top_version;
            8'h04: DAT_O <= reg_key[0];
            8'h05: DAT_O <= reg_key[1];
            8'h06: DAT_O <= reg_key[2];
            8'h07: DAT_O <= reg_key[3];
            8'h08: DAT_O <= reg_key[4];
            8'h09: DAT_O <= reg_key[5];
            8'h0A: DAT_O <= reg_key[6];
            8'h0B: DAT_O <= reg_key[7];
            8'h0C: DAT_O <= reg_nonce[0];
            8'h0D: DAT_O <= reg_nonce[1];
            8'h0E: DAT_O <= reg_nonce[2];
            8'h0F: DAT_O <= reg_counter;
            8'h10: DAT_O <= reg_keystream[0];
            8'h11: DAT_O <= reg_keystream[1];
            8'h12: DAT_O <= reg_keystream[2];
            8'h13: DAT_O <= reg_keystream[3];
            8'h14: DAT_O <= reg_keystream[4];
            8'h15: DAT_O <= reg_keystream[5];
            8'h16: DAT_O <= reg_keystream[6];
            8'h17: DAT_O <= reg_keystream[7];
            8'h18: DAT_O <= reg_keystream[8];
            8'h19: DAT_O <= reg_keystream[9];
            8'h1A: DAT_O <= reg_keystream[10];
            8'h1B: DAT_O <= reg_keystream[11];
            8'h1C: DAT_O <= reg_keystream[12];
            8'h1D: DAT_O <= reg_keystream[13];
            8'h1E: DAT_O <= reg_keystream[14];
            8'h1F: DAT_O <= reg_keystream[15];
            default: DAT_O <= 32'hDEAD_BEEF;
          endcase
        end
      end
    end
  end

endmodule : chacha20_wb
