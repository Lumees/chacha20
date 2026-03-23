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
// ChaCha20 UVM Testbench — Functional Coverage Collector
// =============================================================================

`ifndef CHACHA20_COVERAGE_SV
`define CHACHA20_COVERAGE_SV

`include "uvm_macros.svh"

class chacha20_coverage extends uvm_subscriber #(chacha20_seq_item);

  import chacha20_pkg::*;

  `uvm_component_utils(chacha20_coverage)

  int unsigned cov_counter;
  logic        cov_use_next;

  covergroup cg_chacha20;
    option.per_instance = 1;
    option.name         = "cg_chacha20";
    option.comment      = "ChaCha20 counter and operation coverage";

    cp_counter: coverpoint cov_counter {
      bins zero      = {0};
      bins low       = {[1:10]};
      bins mid       = {[11:100]};
      bins high      = {[101:$]};
    }

    cp_use_next: coverpoint cov_use_next {
      bins init_op = {0};
      bins next_op = {1};
    }

    cx_ctr_op: cross cp_counter, cp_use_next;
  endgroup : cg_chacha20

  function new(string name, uvm_component parent);
    super.new(name, parent);
    cg_chacha20 = new();
  endfunction : new

  function void write(chacha20_seq_item t);
    cov_counter  = t.counter;
    cov_use_next = t.use_next;
    cg_chacha20.sample();

    `uvm_info("COV",
      $sformatf("Sampled: counter=%0d use_next=%0b",
        cov_counter, cov_use_next),
      UVM_DEBUG)
  endfunction : write

  function void report_phase(uvm_phase phase);
    `uvm_info("COV_REPORT",
      $sformatf("cg_chacha20 coverage: %.2f%%", cg_chacha20.get_coverage()),
      UVM_NONE)
  endfunction : report_phase

endclass : chacha20_coverage

`endif // CHACHA20_COVERAGE_SV
