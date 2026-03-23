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
// ChaCha20 UVM Testbench — Environment
// =============================================================================

`ifndef CHACHA20_ENV_SV
`define CHACHA20_ENV_SV

`include "uvm_macros.svh"

class chacha20_env extends uvm_env;

  import chacha20_pkg::*;

  `uvm_component_utils(chacha20_env)

  chacha20_agent       agent;
  chacha20_scoreboard  scoreboard;
  chacha20_coverage    coverage;

  uvm_analysis_port #(chacha20_seq_item) ap_context;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);

    agent      = chacha20_agent::type_id::create      ("agent",      this);
    scoreboard = chacha20_scoreboard::type_id::create  ("scoreboard", this);
    coverage   = chacha20_coverage::type_id::create    ("coverage",   this);

    ap_context = new("ap_context", this);
  endfunction : build_phase

  function void connect_phase(uvm_phase phase);
    agent.monitor.ap_in.connect(scoreboard.ae_in);
    agent.monitor.ap_out.connect(scoreboard.ae_out);
    ap_context.connect(scoreboard.ae_context);
    ap_context.connect(coverage.analysis_export);
  endfunction : connect_phase

  function void start_of_simulation_phase(uvm_phase phase);
    `uvm_info("ENV", "ChaCha20 UVM Environment topology:", UVM_MEDIUM)
    this.print();
  endfunction : start_of_simulation_phase

endclass : chacha20_env

`endif // CHACHA20_ENV_SV
