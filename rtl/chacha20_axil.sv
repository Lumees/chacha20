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
// ChaCha20 IP — AXI4-Lite Interface Wrapper
// =============================================================================
// Register map (32-bit word address, 4-byte aligned):
//
//  Offset  Name           Access  Description
//  0x00    CTRL           R/W     [0]=start(W,self-clear) [1]=next(W,self-clear)
//                                 [2]=busy(RO) [3]=done(RO)
//  0x04    STATUS         RO      Reserved (reads 0)
//  0x08    INFO           RO      [7:0]=key_bits>>3 [15:8]=nonce_bits>>3
//  0x0C    VERSION        RO      IP_VERSION
//  0x10    KEY[0]         R/W     Key word 0 (bits 31:0)
//  0x14    KEY[1]         R/W     Key word 1 (bits 63:32)
//  ...
//  0x2C    KEY[7]         R/W     Key word 7 (bits 255:224)
//  0x30    NONCE[0]       R/W     Nonce word 0 (bits 31:0)
//  0x34    NONCE[1]       R/W     Nonce word 1 (bits 63:32)
//  0x38    NONCE[2]       R/W     Nonce word 2 (bits 95:64)
//  0x3C    COUNTER        R/W     32-bit block counter
//  0x40    KEYSTREAM[0]   RO      Keystream word 0 (bits 31:0)
//  ...
//  0x7C    KEYSTREAM[15]  RO      Keystream word 15 (bits 511:480)
//
// irq: single-cycle output pulse when done transitions 0->1.
// =============================================================================

`timescale 1ns/1ps

import chacha20_pkg::*;

module chacha20_axil (
  input  logic        clk,
  input  logic        rst_n,

  // AXI4-Lite Slave
  input  logic [31:0] s_axil_awaddr,
  input  logic        s_axil_awvalid,
  output logic        s_axil_awready,
  input  logic [31:0] s_axil_wdata,
  input  logic [3:0]  s_axil_wstrb,
  input  logic        s_axil_wvalid,
  output logic        s_axil_wready,
  output logic [1:0]  s_axil_bresp,
  output logic        s_axil_bvalid,
  input  logic        s_axil_bready,
  input  logic [31:0] s_axil_araddr,
  input  logic        s_axil_arvalid,
  output logic        s_axil_arready,
  output logic [31:0] s_axil_rdata,
  output logic [1:0]  s_axil_rresp,
  output logic        s_axil_rvalid,
  input  logic        s_axil_rready,

  // Interrupt — single-cycle pulse when done rises
  output logic        irq
);

  // ── Internal registers ────────────────────────────────────────────────────
  logic [31:0] reg_key       [0:7];    // 256-bit key
  logic [31:0] reg_nonce     [0:2];    // 96-bit nonce
  logic [31:0] reg_counter;            // 32-bit counter
  logic [31:0] reg_keystream [0:15];   // 512-bit keystream
  logic        reg_busy;
  logic        reg_done;

  // ── ChaCha20 engine ──────────────────────────────────────────────────────
  logic             core_start;
  logic             core_next;
  logic             core_busy;
  logic             core_done;
  logic [KEY_W-1:0]   core_key;
  logic [NONCE_W-1:0] core_nonce;
  logic [CTR_W-1:0]   core_ctr;
  logic [BLOCK_W-1:0] core_keystream;
  logic [31:0]       core_version;

  // Pack key, nonce, counter
  always_comb begin
    for (int i = 0; i < 8; i++)
      core_key[i*32 +: 32] = reg_key[i];
    for (int i = 0; i < 3; i++)
      core_nonce[i*32 +: 32] = reg_nonce[i];
    core_ctr = reg_counter;
  end

  chacha20_top u_chacha20 (
    .clk         (clk),
    .rst_n       (rst_n),
    .start_i     (core_start),
    .next_i      (core_next),
    .busy_o      (core_busy),
    .done_o      (core_done),
    .key_i       (core_key),
    .nonce_i     (core_nonce),
    .ctr_i       (core_ctr),
    .keystream_o (core_keystream),
    .version_o   (core_version)
  );

  // ── AXI4-Lite write path ──────────────────────────────────────────────────
  logic [7:0]  wr_addr;
  logic [31:0] wdata_lat;
  logic        aw_active, w_active;

  assign s_axil_awready = !aw_active;
  assign s_axil_wready  = !w_active;
  assign s_axil_bresp   = 2'b00;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      aw_active     <= 1'b0;
      w_active      <= 1'b0;
      wr_addr       <= '0;
      wdata_lat     <= '0;
      s_axil_bvalid <= 1'b0;
      reg_busy      <= 1'b0;
      reg_done      <= 1'b0;
      core_start    <= 1'b0;
      core_next     <= 1'b0;
      reg_counter   <= '0;
      for (int i = 0; i < 8; i++)
        reg_key[i] <= '0;
      for (int i = 0; i < 3; i++)
        reg_nonce[i] <= '0;
      for (int i = 0; i < 16; i++)
        reg_keystream[i] <= '0;
    end else begin
      // AXI4-Lite write handshake
      if (s_axil_awvalid && s_axil_awready) begin
        wr_addr   <= s_axil_awaddr[9:2];
        aw_active <= 1'b1;
      end
      if (s_axil_wvalid && s_axil_wready) begin
        wdata_lat <= s_axil_wdata;
        w_active  <= 1'b1;
      end
      if (s_axil_bvalid && s_axil_bready)
        s_axil_bvalid <= 1'b0;

      // Default pulse deassert
      core_start <= 1'b0;
      core_next  <= 1'b0;

      // Track busy/done
      reg_busy <= core_busy;
      if (core_done) begin
        reg_done <= 1'b1;
        for (int i = 0; i < 16; i++)
          reg_keystream[i] <= core_keystream[i*32 +: 32];
      end

      // Process completed write
      if (aw_active && w_active) begin
        aw_active     <= 1'b0;
        w_active      <= 1'b0;
        s_axil_bvalid <= 1'b1;

        // CTRL register (offset 0x00)
        if (wr_addr == 8'h00) begin
          if (wdata_lat[0] && !reg_busy) begin
            core_start <= 1'b1;
            reg_done   <= 1'b0;
          end
          if (wdata_lat[1] && !reg_busy) begin
            core_next  <= 1'b1;
            reg_done   <= 1'b0;
          end
        end

        // KEY[0..7] at 0x10..0x2C (word addr 0x04..0x0B)
        if (wr_addr >= 8'h04 && wr_addr <= 8'h0B)
          reg_key[wr_addr[2:0]] <= wdata_lat;

        // NONCE[0..2] at 0x30..0x38 (word addr 0x0C..0x0E)
        if (wr_addr >= 8'h0C && wr_addr <= 8'h0E)
          reg_nonce[wr_addr[1:0]] <= wdata_lat;

        // COUNTER at 0x3C (word addr 0x0F)
        if (wr_addr == 8'h0F)
          reg_counter <= wdata_lat;
      end
    end
  end

  // ── Interrupt ─────────────────────────────────────────────────────────────
  logic done_prev;
  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      done_prev <= 1'b0;
      irq       <= 1'b0;
    end else begin
      done_prev <= reg_done;
      irq       <= reg_done & ~done_prev;
    end
  end

  // ── AXI4-Lite read logic ──────────────────────────────────────────────────
  assign s_axil_rresp = 2'b00;

  always_ff @(posedge clk or negedge rst_n) begin
    if (!rst_n) begin
      s_axil_arready <= 1'b1;
      s_axil_rvalid  <= 1'b0;
      s_axil_rdata   <= '0;
    end else begin
      if (s_axil_arvalid && s_axil_arready) begin
        s_axil_arready <= 1'b0;
        s_axil_rvalid  <= 1'b1;

        unique case (s_axil_araddr[9:2])
          8'h00: s_axil_rdata <= {28'h0, reg_done, reg_busy, 2'b00};   // CTRL
          8'h01: s_axil_rdata <= 32'h0;                                  // STATUS
          8'h02: s_axil_rdata <= {16'h0, 8'd12, 8'd32};                // INFO
          8'h03: s_axil_rdata <= core_version;                           // VERSION
          // KEY[0..7]
          8'h04: s_axil_rdata <= reg_key[0];
          8'h05: s_axil_rdata <= reg_key[1];
          8'h06: s_axil_rdata <= reg_key[2];
          8'h07: s_axil_rdata <= reg_key[3];
          8'h08: s_axil_rdata <= reg_key[4];
          8'h09: s_axil_rdata <= reg_key[5];
          8'h0A: s_axil_rdata <= reg_key[6];
          8'h0B: s_axil_rdata <= reg_key[7];
          // NONCE[0..2]
          8'h0C: s_axil_rdata <= reg_nonce[0];
          8'h0D: s_axil_rdata <= reg_nonce[1];
          8'h0E: s_axil_rdata <= reg_nonce[2];
          // COUNTER
          8'h0F: s_axil_rdata <= reg_counter;
          // KEYSTREAM[0..15]
          8'h10: s_axil_rdata <= reg_keystream[0];
          8'h11: s_axil_rdata <= reg_keystream[1];
          8'h12: s_axil_rdata <= reg_keystream[2];
          8'h13: s_axil_rdata <= reg_keystream[3];
          8'h14: s_axil_rdata <= reg_keystream[4];
          8'h15: s_axil_rdata <= reg_keystream[5];
          8'h16: s_axil_rdata <= reg_keystream[6];
          8'h17: s_axil_rdata <= reg_keystream[7];
          8'h18: s_axil_rdata <= reg_keystream[8];
          8'h19: s_axil_rdata <= reg_keystream[9];
          8'h1A: s_axil_rdata <= reg_keystream[10];
          8'h1B: s_axil_rdata <= reg_keystream[11];
          8'h1C: s_axil_rdata <= reg_keystream[12];
          8'h1D: s_axil_rdata <= reg_keystream[13];
          8'h1E: s_axil_rdata <= reg_keystream[14];
          8'h1F: s_axil_rdata <= reg_keystream[15];
          default: s_axil_rdata <= 32'hDEAD_BEEF;
        endcase
      end
      if (s_axil_rvalid && s_axil_rready) begin
        s_axil_rvalid  <= 1'b0;
        s_axil_arready <= 1'b1;
      end
    end
  end

endmodule : chacha20_axil
