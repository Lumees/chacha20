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
// ChaCha20 UVM Testbench — Top-level Module
// =============================================================================

`timescale 1ns/1ps

`include "uvm_macros.svh"

import uvm_pkg::*;
import chacha20_pkg::*;

// Include all testbench files in order of dependency
`include "chacha20_seq_item.sv"
`include "chacha20_if.sv"
`include "chacha20_driver.sv"
`include "chacha20_monitor.sv"
`include "chacha20_scoreboard.sv"
`include "chacha20_coverage.sv"
`include "chacha20_agent.sv"
`include "chacha20_env.sv"
`include "chacha20_sequences.sv"
`include "chacha20_tests.sv"

module chacha20_tb_top;

  // ---------------------------------------------------------------------------
  // Clock and reset
  // ---------------------------------------------------------------------------
  logic clk;
  logic rst_n;

  // 10 ns period -> 100 MHz
  initial clk = 1'b0;
  always #5ns clk = ~clk;

  // Reset: assert for 10 cycles, then release
  initial begin
    rst_n = 1'b0;
    repeat (10) @(posedge clk);
    @(negedge clk);
    rst_n = 1'b1;
    `uvm_info("TB_TOP", "Reset deasserted", UVM_MEDIUM)
  end

  // ---------------------------------------------------------------------------
  // Virtual interface instantiation
  // ---------------------------------------------------------------------------
  chacha20_if dut_if (.clk(clk), .rst_n(rst_n));

  // ---------------------------------------------------------------------------
  // DUT instantiation
  // ---------------------------------------------------------------------------
  chacha20_top dut (
    .clk         (clk),
    .rst_n       (rst_n),

    .start_i     (dut_if.start_i),
    .next_i      (dut_if.next_i),
    .busy_o      (dut_if.busy_o),
    .done_o      (dut_if.done_o),

    .key_i       (dut_if.key_i),
    .nonce_i     (dut_if.nonce_i),
    .ctr_i       (dut_if.ctr_i),

    .keystream_o (dut_if.keystream_o),
    .version_o   (dut_if.version_o)
  );

  // ---------------------------------------------------------------------------
  // UVM config_db: register virtual interface
  // ---------------------------------------------------------------------------
  initial begin
    uvm_config_db #(virtual chacha20_if)::set(
      null,
      "uvm_test_top.*",
      "vif",
      dut_if
    );

    `uvm_info("TB_TOP",
      "ChaCha20 DUT instantiated, vif registered in config_db",
      UVM_MEDIUM)
  end

  // ---------------------------------------------------------------------------
  // Simulation timeout watchdog
  // ---------------------------------------------------------------------------
  initial begin
    #10ms;
    `uvm_fatal("WATCHDOG", "Simulation timeout — check for protocol deadlock")
  end

  // ---------------------------------------------------------------------------
  // Start UVM test
  // ---------------------------------------------------------------------------
  initial begin
    run_test();
  end

endmodule : chacha20_tb_top
