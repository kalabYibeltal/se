// Copyright lowRISC contributors.
// Licensed under the Apache License, Version 2.0, see LICENSE for details.
// SPDX-License-Identifier: Apache-2.0

/**
 * Secure ALU Wrapper with AES-128 Encryption/Decryption
 * 
 * This module wraps the standard ibex_alu with AES-128 encryption/decryption.
 * Flow: Encrypted Operands -> Decrypt -> ALU Operation -> Encrypt -> Output
 */

module ibex_alu_secure #(
  parameter ibex_pkg::rv32b_e RV32B = ibex_pkg::RV32BNone,
  parameter bit EnableCrypto = 1'b1  // Enable/disable crypto for testing
) (
  input  logic              clk_i,
  input  logic              rst_ni,
  
  // AES Key interface
  input  logic [127:0]      aes_key_i,
  input  logic              aes_key_valid_i,
  
  // ALU interface (same as ibex_alu)
  input  ibex_pkg::alu_op_e operator_i,
  input  logic [31:0]       operand_a_i,      // Encrypted operand A
  input  logic [31:0]       operand_b_i,      // Encrypted operand B
  
  input  logic              instr_first_cycle_i,
  
  input  logic [32:0]       multdiv_operand_a_i,
  input  logic [32:0]       multdiv_operand_b_i,
  input  logic              multdiv_sel_i,
  
  input  logic [31:0]       imd_val_q_i[2],
  output logic [31:0]       imd_val_d_o[2],
  output logic [1:0]        imd_val_we_o,
  
  output logic [31:0]       adder_result_o,
  output logic [33:0]       adder_result_ext_o,
  
  output logic [31:0]       result_o,          // Encrypted result
  output logic              comparison_result_o,
  output logic              is_equal_result_o,
  
  // Status signals
  output logic              crypto_busy_o,
  output logic              crypto_error_o     // Set if key not valid
);

  import ibex_pkg::*;

  // Decrypted operands
  logic [31:0] operand_a_dec;
  logic [31:0] operand_b_dec;
  
  // ALU result (plaintext)
  logic [31:0] alu_result_plain;
  logic [31:0] alu_adder_result_plain;
  logic [33:0] alu_adder_result_ext_plain;
  logic [31:0] alu_result_encrypted;
  
  // Crypto control signals
  logic        start_decrypt;
  logic        decrypt_a_valid, decrypt_b_valid;
  logic        encrypt_valid, encrypt_done;
  
  // AES units interface signals
  logic [127:0] decrypt_a_in, decrypt_a_out;
  logic [127:0] decrypt_b_in, decrypt_b_out;
  logic [127:0] encrypt_in, encrypt_out;
  
  // Pipeline state machine
  typedef enum logic [2:0] {
    IDLE,
    DECRYPT_OPS,
    WAIT_DECRYPT,
    ALU_COMPUTE,
    ENCRYPT_RESULT,
    WAIT_ENCRYPT
  } crypto_state_e;
  
  crypto_state_e crypto_state_q, crypto_state_d;
  
  // Registers to hold results during crypto operations
  logic [31:0] alu_result_reg_q, alu_result_reg_d;
  logic [31:0] alu_adder_result_reg_q, alu_adder_result_reg_d;
  logic [33:0] alu_adder_result_ext_reg_q, alu_adder_result_ext_reg_d;
  logic        comparison_result_reg_q, comparison_result_reg_d;
  logic        is_equal_result_reg_q, is_equal_result_reg_d;
  
  // Error detection
  assign crypto_error_o = EnableCrypto & ~aes_key_valid_i;
  
  //////////////////////////////////
  // State Machine for Crypto FSM //
  //////////////////////////////////
  
  always_comb begin
    crypto_state_d = crypto_state_q;
    start_decrypt = 1'b0;
    encrypt_valid = 1'b0;
    crypto_busy_o = 1'b0;
    
    alu_result_reg_d = alu_result_reg_q;
    alu_adder_result_reg_d = alu_adder_result_reg_q;
    alu_adder_result_ext_reg_d = alu_adder_result_ext_reg_q;
    comparison_result_reg_d = comparison_result_reg_q;
    is_equal_result_reg_d = is_equal_result_reg_q;
    
    case (crypto_state_q)
      IDLE: begin
        if (instr_first_cycle_i) begin
          if (EnableCrypto && aes_key_valid_i) begin
            crypto_state_d = DECRYPT_OPS;
            start_decrypt = 1'b1;
            crypto_busy_o = 1'b1;
          end else begin
            // Bypass crypto if disabled or key not valid
            crypto_state_d = IDLE;
          end
        end
      end
      
      DECRYPT_OPS: begin
        crypto_busy_o = 1'b1;
        crypto_state_d = WAIT_DECRYPT;
      end
      
      WAIT_DECRYPT: begin
        crypto_busy_o = 1'b1;
        if (decrypt_a_valid && decrypt_b_valid) begin
          crypto_state_d = ALU_COMPUTE;
        end
      end
      
      ALU_COMPUTE: begin
        crypto_busy_o = 1'b1;
        // Store ALU results
        alu_result_reg_d = alu_result_plain;
        alu_adder_result_reg_d = alu_adder_result_plain;
        alu_adder_result_ext_reg_d = alu_adder_result_ext_plain;
        comparison_result_reg_d = comparison_result_o;
        is_equal_result_reg_d = is_equal_result_o;
        
        crypto_state_d = ENCRYPT_RESULT;
        encrypt_valid = 1'b1;
      end
      
      ENCRYPT_RESULT: begin
        crypto_busy_o = 1'b1;
        crypto_state_d = WAIT_ENCRYPT;
      end
      
      WAIT_ENCRYPT: begin
        crypto_busy_o = 1'b1;
        if (encrypt_done) begin
          crypto_state_d = IDLE;
        end
      end
      
      default: crypto_state_d = IDLE;
    endcase
  end
  
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      crypto_state_q <= IDLE;
      alu_result_reg_q <= 32'h0;
      alu_adder_result_reg_q <= 32'h0;
      alu_adder_result_ext_reg_q <= 34'h0;
      comparison_result_reg_q <= 1'b0;
      is_equal_result_reg_q <= 1'b0;
    end else begin
      crypto_state_q <= crypto_state_d;
      alu_result_reg_q <= alu_result_reg_d;
      alu_adder_result_reg_q <= alu_adder_result_reg_d;
      alu_adder_result_ext_reg_q <= alu_adder_result_ext_reg_d;
      comparison_result_reg_q <= comparison_result_reg_d;
      is_equal_result_reg_q <= is_equal_result_reg_d;
    end
  end
  
  ///////////////////////////////
  // AES Decryption for Operands
  ///////////////////////////////
  
  // Pad 32-bit operands to 128-bit for AES
  assign decrypt_a_in = {96'h0, operand_a_i};
  assign decrypt_b_in = {96'h0, operand_b_i};
  
  aes128_cipher  decrypt_a_unit (
    .clk_i      (clk_i),
    .rst_ni     (rst_ni),
    .key_i      (aes_key_i),
    .data_i     (decrypt_a_in),
    .decrypt_i  (1'b1),              // Decrypt mode
    .data_o     (decrypt_a_out),
    .valid_i    (start_decrypt),
    .valid_o    (decrypt_a_valid)
  );
  
  aes128_cipher  decrypt_b_unit (
    .clk_i      (clk_i),
    .rst_ni     (rst_ni),
    .key_i      (aes_key_i),
    .data_i     (decrypt_b_in),
    .decrypt_i  (1'b1),              // Decrypt mode
    .valid_i    (start_decrypt),
    .data_o     (decrypt_b_out),
    .valid_o    (decrypt_b_valid)
  );
  
  // Extract 32-bit plaintext from 128-bit output
  assign operand_a_dec = EnableCrypto ? decrypt_a_out[31:0] : operand_a_i;
  assign operand_b_dec = EnableCrypto ? decrypt_b_out[31:0] : operand_b_i;
  
  ////////////////////////
  // Standard ALU Core  //
  ////////////////////////
  
  ibex_alu #(
    .RV32B(RV32B)
  ) alu_core_i (
    .operator_i           (operator_i),
    .operand_a_i          (operand_a_dec),
    .operand_b_i          (operand_b_dec),
    .instr_first_cycle_i  (instr_first_cycle_i),
    .multdiv_operand_a_i  (multdiv_operand_a_i),
    .multdiv_operand_b_i  (multdiv_operand_b_i),
    .multdiv_sel_i        (multdiv_sel_i),
    .imd_val_q_i          (imd_val_q_i),
    .imd_val_d_o          (imd_val_d_o),
    .imd_val_we_o         (imd_val_we_o),
    .adder_result_o       (alu_adder_result_plain),
    .adder_result_ext_o   (alu_adder_result_ext_plain),
    .result_o             (alu_result_plain),
    .comparison_result_o  (comparison_result_o),
    .is_equal_result_o    (is_equal_result_o)
  );
  
  ///////////////////////////
  // AES Encryption for Result
  ///////////////////////////
  
  // Pad result to 128-bit for AES
  assign encrypt_in = {96'h0, alu_result_reg_q};
  
  aes128_cipher  encrypt_unit (
    .clk_i      (clk_i),
    .rst_ni     (rst_ni),
    .key_i      (aes_key_i),
    .data_i     (encrypt_in),
    .decrypt_i  (1'b0),              // Encrypt mode
    .valid_i    (encrypt_valid),
    .data_o     (encrypt_out),
    .valid_o    (encrypt_done)
  );
  
  // Extract 32-bit ciphertext from 128-bit output
  assign alu_result_encrypted = encrypt_out[31:0];
  
  // Output mux: encrypted or plaintext based on EnableCrypto
  assign result_o = EnableCrypto ? alu_result_encrypted : alu_result_plain;
  assign adder_result_o = EnableCrypto ? alu_adder_result_reg_q : alu_adder_result_plain;
  assign adder_result_ext_o = EnableCrypto ? alu_adder_result_ext_reg_q : alu_adder_result_ext_plain;

endmodule