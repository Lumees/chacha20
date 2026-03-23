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
// ChaCha20 UVM Testbench — Driver
// =============================================================================

`ifndef CHACHA20_DRIVER_SV
`define CHACHA20_DRIVER_SV

`include "uvm_macros.svh"

class chacha20_driver extends uvm_driver #(chacha20_seq_item);

  import chacha20_pkg::*;

  `uvm_component_utils(chacha20_driver)

  virtual chacha20_if vif;
  localparam int DONE_TIMEOUT = 5000;

  function new(string name, uvm_component parent);
    super.new(name, parent);
  endfunction : new

  function void build_phase(uvm_phase phase);
    super.build_phase(phase);
    if (!uvm_config_db #(virtual chacha20_if)::get(this, "", "vif", vif))
      `uvm_fatal("NOVIF", "chacha20_driver: cannot get virtual interface")
  endfunction : build_phase

  task run_phase(uvm_phase phase);
    chacha20_seq_item req, rsp;

    vif.driver_cb.start_i <= 1'b0;
    vif.driver_cb.next_i  <= 1'b0;
    vif.driver_cb.key_i   <= '0;
    vif.driver_cb.nonce_i <= '0;
    vif.driver_cb.ctr_i   <= '0;

    @(posedge vif.clk);
    wait (vif.rst_n === 1'b1);
    @(posedge vif.clk);

    forever begin
      seq_item_port.get_next_item(req);
      `uvm_info("DRV", $sformatf("Driving: %s", req.convert2string()), UVM_HIGH)

      rsp = chacha20_seq_item::type_id::create("rsp");
      rsp.copy(req);

      @(vif.driver_cb);
      vif.driver_cb.key_i   <= req.key;
      vif.driver_cb.nonce_i <= req.nonce;
      vif.driver_cb.ctr_i   <= req.counter;

      if (req.use_next)
        vif.driver_cb.next_i <= 1'b1;
      else
        vif.driver_cb.start_i <= 1'b1;

      @(vif.driver_cb);
      vif.driver_cb.start_i <= 1'b0;
      vif.driver_cb.next_i  <= 1'b0;

      // Wait for done
      begin
        int timeout = 0;
        while (!vif.driver_cb.done_o) begin
          @(vif.driver_cb);
          timeout++;
          if (timeout >= DONE_TIMEOUT)
            `uvm_fatal("DRV_TIMEOUT",
              $sformatf("done_o never asserted after %0d cycles", DONE_TIMEOUT))
        end
      end

      rsp.actual_keystream = vif.driver_cb.keystream_o;
      `uvm_info("DRV",
        $sformatf("Keystream captured: %h", rsp.actual_keystream), UVM_HIGH)

      seq_item_port.item_done(rsp);
    end
  endtask : run_phase

endclass : chacha20_driver

`endif // CHACHA20_DRIVER_SV
