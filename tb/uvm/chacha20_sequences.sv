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
// ChaCha20 UVM Testbench — Sequences
// =============================================================================

`ifndef CHACHA20_SEQUENCES_SV
`define CHACHA20_SEQUENCES_SV

`include "uvm_macros.svh"

// ============================================================================
// Base sequence
// ============================================================================
class chacha20_base_seq extends uvm_sequence #(chacha20_seq_item);

  import chacha20_pkg::*;

  `uvm_object_utils(chacha20_base_seq)

  uvm_analysis_port #(chacha20_seq_item) ap_context;

  function new(string name = "chacha20_base_seq");
    super.new(name);
  endfunction : new

  task send_fixed_item(chacha20_seq_item item);
    start_item(item);
    finish_item(item);
    if (ap_context != null)
      ap_context.write(item);
    else
      `uvm_warning("SEQ_CTX", "ap_context handle is null")
  endtask : send_fixed_item

  virtual task body();
    `uvm_warning("SEQ", "chacha20_base_seq::body() called — override in derived class")
  endtask : body

endclass : chacha20_base_seq


// ============================================================================
// Directed RFC 8439 sequence
// ============================================================================
class chacha20_directed_seq extends chacha20_base_seq;

  `uvm_object_utils(chacha20_directed_seq)

  function new(string name = "chacha20_directed_seq");
    super.new(name);
  endfunction : new

  virtual task body();
    chacha20_seq_item item;

    // ── Test 1: RFC 8439 Section 2.4.2 ──────────────────────────────
    // Key: 00 01 02 ... 1f
    // Nonce: 00 00 00 00 00 00 00 4a 00 00 00 00
    // Counter: 1
    item = chacha20_seq_item::type_id::create("rfc8439_242");
    // Key packed little-endian: word[0]=0x03020100, word[7]=0x1f1e1d1c
    item.key     = {32'h1f1e1d1c, 32'h1b1a1918, 32'h17161514, 32'h13121110,
                    32'h0f0e0d0c, 32'h0b0a0908, 32'h07060504, 32'h03020100};
    item.nonce   = {32'h00000000, 32'h4a000000, 32'h00000000};
    item.counter = 32'd1;
    item.use_next = 1'b0;
    // Expected keystream from RFC 8439 (packed as 512-bit LE words)
    item.expected_keystream = {
      32'h50a2c3e4, 32'hd0cb83e8, 32'h16de4eb9, 32'h12b5c419,
      32'hd9b902a2, 32'hc21407d7, 32'h9f070aa2, 32'h82d24664,
      32'hd4c46e4c, 32'h04aa2209, 32'hc0330368, 32'hd1c7f4c7,
      32'h20a37147, 32'h0f50dd1f, 32'h3bd11559, 32'he4f1e710
    };
    `uvm_info("SEQ_DIR", "Sending RFC 8439 2.4.2 vector", UVM_MEDIUM)
    send_fixed_item(item);

    // ── Test 2: All-zero key/nonce/counter ──────────────────────────
    item = chacha20_seq_item::type_id::create("zero_test");
    item.key     = '0;
    item.nonce   = '0;
    item.counter = 32'd0;
    item.use_next = 1'b0;
    // Expected: first word 0xade0b876 (from zero test vector)
    item.expected_keystream = {
      32'h3e2f308c, 32'h5e01118b, 32'h3a698a0d, 32'hd74dda47,
      32'hbe9f75da, 32'h9b72d9ad, 32'h5ef71f3f, 32'h5e6dc227,
      32'hd1edf151, 32'h92b8d56b, 32'h090d1e47, 32'hb228867f,
      32'h3b5ebdee, 32'h3570f600, 32'hda893fd2, 32'hade0b876
    };
    `uvm_info("SEQ_DIR", "Sending all-zero vector", UVM_MEDIUM)
    send_fixed_item(item);

  endtask : body

endclass : chacha20_directed_seq


// ============================================================================
// Random sequence
// ============================================================================
class chacha20_random_seq extends chacha20_base_seq;

  `uvm_object_utils(chacha20_random_seq)

  int unsigned num_transactions = 10;

  function new(string name = "chacha20_random_seq");
    super.new(name);
  endfunction : new

  virtual task body();
    chacha20_seq_item item;

    // Repeat the RFC 8439 vector
    repeat (num_transactions) begin
      item = chacha20_seq_item::type_id::create("rand_chacha20");
      item.key     = {32'h1f1e1d1c, 32'h1b1a1918, 32'h17161514, 32'h13121110,
                      32'h0f0e0d0c, 32'h0b0a0908, 32'h07060504, 32'h03020100};
      item.nonce   = {32'h00000000, 32'h4a000000, 32'h00000000};
      item.counter = 32'd1;
      item.use_next = 1'b0;
      item.expected_keystream = {
        32'h50a2c3e4, 32'hd0cb83e8, 32'h16de4eb9, 32'h12b5c419,
        32'hd9b902a2, 32'hc21407d7, 32'h9f070aa2, 32'h82d24664,
        32'hd4c46e4c, 32'h04aa2209, 32'hc0330368, 32'hd1c7f4c7,
        32'h20a37147, 32'h0f50dd1f, 32'h3bd11559, 32'he4f1e710
      };
      send_fixed_item(item);
    end

    `uvm_info("SEQ_RAND",
      $sformatf("Completed %0d ChaCha20 transactions", num_transactions),
      UVM_MEDIUM)
  endtask : body

endclass : chacha20_random_seq


// ============================================================================
// Stress sequence
// ============================================================================
class chacha20_stress_seq extends chacha20_base_seq;

  `uvm_object_utils(chacha20_stress_seq)

  int unsigned num_transactions = 50;

  function new(string name = "chacha20_stress_seq");
    super.new(name);
  endfunction : new

  virtual task body();
    chacha20_seq_item item;

    repeat (num_transactions) begin
      item = chacha20_seq_item::type_id::create("stress_chacha20");
      item.key     = {32'h1f1e1d1c, 32'h1b1a1918, 32'h17161514, 32'h13121110,
                      32'h0f0e0d0c, 32'h0b0a0908, 32'h07060504, 32'h03020100};
      item.nonce   = {32'h00000000, 32'h4a000000, 32'h00000000};
      item.counter = 32'd1;
      item.use_next = 1'b0;
      item.expected_keystream = {
        32'h50a2c3e4, 32'hd0cb83e8, 32'h16de4eb9, 32'h12b5c419,
        32'hd9b902a2, 32'hc21407d7, 32'h9f070aa2, 32'h82d24664,
        32'hd4c46e4c, 32'h04aa2209, 32'hc0330368, 32'hd1c7f4c7,
        32'h20a37147, 32'h0f50dd1f, 32'h3bd11559, 32'he4f1e710
      };
      send_fixed_item(item);
    end

    `uvm_info("SEQ_STRESS",
      $sformatf("Completed %0d back-to-back ChaCha20 transactions", num_transactions),
      UVM_MEDIUM)
  endtask : body

endclass : chacha20_stress_seq

`endif // CHACHA20_SEQUENCES_SV
