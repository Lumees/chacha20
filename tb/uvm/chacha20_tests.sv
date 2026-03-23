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
// ChaCha20 UVM Testbench — Tests
// =============================================================================

`ifndef CHACHA20_TESTS_SV
`define CHACHA20_TESTS_SV

`include "uvm_macros.svh"

// ============================================================================
// Base test
// ============================================================================
class chacha20_base_test extends uvm_test;

  import chacha20_pkg::*;

  `uvm_component_utils(chacha20_base_test)

  chacha20_env env;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    env = chacha20_env::type_id::create("env", this);
  endfunction : build_phase

  function void start_of_simulation_phase(uvm_phase phase);
    `uvm_info("TEST", "=== ChaCha20 UVM Testbench ===", UVM_NONE)
    `uvm_info("TEST", "UVM component topology:", UVM_MEDIUM)
    uvm_top.print_topology();
  endfunction : start_of_simulation_phase

  function void connect_seq_context(chacha20_base_seq seq);
    seq.ap_context = env.ap_context;
  endfunction : connect_seq_context

  virtual task run_phase(uvm_phase phase);
    `uvm_warning("TEST", "chacha20_base_test::run_phase — no sequences run")
  endtask : run_phase

  function void report_phase(uvm_phase phase);
    uvm_report_server svr;
    svr = uvm_report_server::get_server();
    if (svr.get_severity_count(UVM_FATAL) + svr.get_severity_count(UVM_ERROR) > 0)
      `uvm_info("TEST", "*** TEST FAILED ***", UVM_NONE)
    else
      `uvm_info("TEST", "*** TEST PASSED ***", UVM_NONE)
  endfunction : report_phase

endclass : chacha20_base_test


// ============================================================================
// Directed test
// ============================================================================
class chacha20_directed_test extends chacha20_base_test;

  `uvm_component_utils(chacha20_directed_test)

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  virtual task run_phase(uvm_phase phase);
    chacha20_directed_seq dir_seq;

    phase.raise_objection(this, "chacha20_directed_test started");

    dir_seq = chacha20_directed_seq::type_id::create("dir_seq");
    connect_seq_context(dir_seq);

    `uvm_info("DIR_TEST", "Running directed ChaCha20 RFC 8439 sequences", UVM_MEDIUM)
    dir_seq.start(env.agent.sequencer);

    #500ns;
    phase.drop_objection(this, "chacha20_directed_test complete");
  endtask : run_phase

endclass : chacha20_directed_test


// ============================================================================
// Random test
// ============================================================================
class chacha20_random_test extends chacha20_base_test;

  `uvm_component_utils(chacha20_random_test)

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  virtual task run_phase(uvm_phase phase);
    chacha20_random_seq rand_seq;

    phase.raise_objection(this, "chacha20_random_test started");

    rand_seq = chacha20_random_seq::type_id::create("rand_seq");
    connect_seq_context(rand_seq);
    rand_seq.num_transactions = 20;

    `uvm_info("RAND_TEST", "Running 20 ChaCha20 transactions", UVM_MEDIUM)
    rand_seq.start(env.agent.sequencer);

    #500ns;
    phase.drop_objection(this, "chacha20_random_test complete");
  endtask : run_phase

endclass : chacha20_random_test


// ============================================================================
// Stress test
// ============================================================================
class chacha20_stress_test extends chacha20_base_test;

  `uvm_component_utils(chacha20_stress_test)

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    uvm_top.set_report_verbosity_level_hier(UVM_MEDIUM);
  endfunction : build_phase

  virtual task run_phase(uvm_phase phase);
    chacha20_stress_seq stress_seq;

    phase.raise_objection(this, "chacha20_stress_test started");

    stress_seq = chacha20_stress_seq::type_id::create("stress_seq");
    connect_seq_context(stress_seq);
    stress_seq.num_transactions = 100;

    `uvm_info("STRESS_TEST", "Running 100 back-to-back ChaCha20 transactions", UVM_MEDIUM)
    stress_seq.start(env.agent.sequencer);

    #5000ns;
    phase.drop_objection(this, "chacha20_stress_test complete");
  endtask : run_phase

endclass : chacha20_stress_test

`endif // CHACHA20_TESTS_SV
