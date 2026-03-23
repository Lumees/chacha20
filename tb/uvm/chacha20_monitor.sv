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
// ChaCha20 UVM Testbench — Monitor
// =============================================================================

`ifndef CHACHA20_MONITOR_SV
`define CHACHA20_MONITOR_SV

`include "uvm_macros.svh"

class chacha20_monitor extends uvm_monitor;

  import chacha20_pkg::*;

  `uvm_component_utils(chacha20_monitor)

  uvm_analysis_port #(chacha20_seq_item) ap_in;
  uvm_analysis_port #(chacha20_seq_item) ap_out;

  virtual chacha20_if vif;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    ap_in  = new("ap_in",  this);
    ap_out = new("ap_out", this);

    if (!uvm_config_db #(virtual chacha20_if)::get(this, "", "vif", vif))
      `uvm_fatal("NOVIF", "chacha20_monitor: cannot get virtual interface")
  endfunction : build_phase

  task run_phase(uvm_phase phase);
    fork
      monitor_input();
      monitor_output();
    join
  endtask : run_phase

  task monitor_input();
    chacha20_seq_item item;
    forever begin
      @(vif.monitor_cb);
      if (vif.monitor_cb.start_i === 1'b1 || vif.monitor_cb.next_i === 1'b1) begin
        item = chacha20_seq_item::type_id::create("mon_in_item");
        `uvm_info("MON_IN",
          $sformatf("Input captured (start=%0b next=%0b)",
            vif.monitor_cb.start_i, vif.monitor_cb.next_i),
          UVM_HIGH)
        ap_in.write(item);
      end
    end
  endtask : monitor_input

  task monitor_output();
    chacha20_seq_item item;
    forever begin
      @(vif.monitor_cb);
      if (vif.monitor_cb.done_o === 1'b1) begin
        item = chacha20_seq_item::type_id::create("mon_out_item");
        item.actual_keystream = vif.monitor_cb.keystream_o;

        `uvm_info("MON_OUT",
          $sformatf("Keystream output: %h", item.actual_keystream), UVM_HIGH)
        ap_out.write(item);
      end
    end
  endtask : monitor_output

endclass : chacha20_monitor

`endif // CHACHA20_MONITOR_SV
