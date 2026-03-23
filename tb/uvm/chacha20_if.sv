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
// ChaCha20 UVM Testbench — Virtual Interface
// =============================================================================

`timescale 1ns/1ps

interface chacha20_if (input logic clk, input logic rst_n);

  import chacha20_pkg::*;

  // DUT ports
  logic              start_i;
  logic              next_i;
  logic              busy_o;
  logic              done_o;
  logic [KEY_W-1:0]   key_i;
  logic [NONCE_W-1:0] nonce_i;
  logic [CTR_W-1:0]   ctr_i;
  logic [BLOCK_W-1:0] keystream_o;
  logic [31:0]       version_o;

  // Driver clocking block
  clocking driver_cb @(posedge clk);
    default input  #1step
            output #1step;

    output start_i;
    output next_i;
    output key_i;
    output nonce_i;
    output ctr_i;
    input  busy_o;
    input  done_o;
    input  keystream_o;
    input  version_o;
  endclocking : driver_cb

  // Monitor clocking block
  clocking monitor_cb @(posedge clk);
    default input #1step;

    input start_i;
    input next_i;
    input key_i;
    input nonce_i;
    input ctr_i;
    input busy_o;
    input done_o;
    input keystream_o;
    input version_o;
  endclocking : monitor_cb

  modport driver_mp  (clocking driver_cb,  input clk, input rst_n);
  modport monitor_mp (clocking monitor_cb, input clk, input rst_n);

endinterface : chacha20_if
