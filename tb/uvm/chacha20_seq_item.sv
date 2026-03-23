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
// ChaCha20 UVM Testbench — Sequence Item
// =============================================================================

`ifndef CHACHA20_SEQ_ITEM_SV
`define CHACHA20_SEQ_ITEM_SV

`include "uvm_macros.svh"

class chacha20_seq_item extends uvm_sequence_item;

  import chacha20_pkg::*;

  `uvm_object_utils_begin(chacha20_seq_item)
    `uvm_field_int (key,               UVM_ALL_ON | UVM_HEX)
    `uvm_field_int (nonce,             UVM_ALL_ON | UVM_HEX)
    `uvm_field_int (counter,           UVM_ALL_ON | UVM_HEX)
    `uvm_field_int (expected_keystream, UVM_ALL_ON | UVM_HEX)
    `uvm_field_int (actual_keystream,   UVM_ALL_ON | UVM_HEX)
  `uvm_object_utils_end

  // Stimulus
  logic [KEY_W-1:0]   key;
  logic [NONCE_W-1:0] nonce;
  logic [CTR_W-1:0]   counter;
  logic               use_next;    // 0=init, 1=next

  // Results
  logic [BLOCK_W-1:0] expected_keystream;
  logic [BLOCK_W-1:0] actual_keystream;

  function new(string name = "chacha20_seq_item");
    super.new(name);
    use_next = 1'b0;
  endfunction : new

  function string convert2string();
    return $sformatf(
      "ChaCha20 | ctr=%0d | exp=%h act=%h",
      counter, expected_keystream, actual_keystream
    );
  endfunction : convert2string

endclass : chacha20_seq_item

`endif // CHACHA20_SEQ_ITEM_SV
