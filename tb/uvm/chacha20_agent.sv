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
// ChaCha20 UVM Testbench — Agent
// =============================================================================

`ifndef CHACHA20_AGENT_SV
`define CHACHA20_AGENT_SV

`include "uvm_macros.svh"

class chacha20_agent extends uvm_agent;

  import chacha20_pkg::*;

  `uvm_component_utils(chacha20_agent)

  chacha20_driver                     driver;
  chacha20_monitor                    monitor;
  uvm_sequencer #(chacha20_seq_item)  sequencer;

  virtual chacha20_if vif;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);

    if (!uvm_config_db #(virtual chacha20_if)::get(this, "", "vif", vif))
      `uvm_fatal("NOVIF", "chacha20_agent: cannot get virtual interface")

    monitor = chacha20_monitor::type_id::create("monitor", this);

    if (get_is_active() == UVM_ACTIVE) begin
      driver    = chacha20_driver::type_id::create("driver",    this);
      sequencer = uvm_sequencer #(chacha20_seq_item)::type_id::create("sequencer", this);
    end
  endfunction : build_phase

  function void connect_phase(uvm_phase phase);
    uvm_config_db #(virtual chacha20_if)::set(this, "driver",  "vif", vif);
    uvm_config_db #(virtual chacha20_if)::set(this, "monitor", "vif", vif);

    if (get_is_active() == UVM_ACTIVE) begin
      driver.seq_item_port.connect(sequencer.seq_item_export);
    end
  endfunction : connect_phase

  function void start_of_simulation_phase(uvm_phase phase);
    `uvm_info("AGENT",
      $sformatf("chacha20_agent is %s",
        (get_is_active() == UVM_ACTIVE) ? "ACTIVE" : "PASSIVE"),
      UVM_MEDIUM)
  endfunction : start_of_simulation_phase

endclass : chacha20_agent

`endif // CHACHA20_AGENT_SV
