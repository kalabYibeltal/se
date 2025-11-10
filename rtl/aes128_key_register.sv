
/**
 * AES-128 Key Register
 * 
 * Holds the 128-bit AES key for encryption/decryption operations
 * Key can be loaded via a dedicated interface
 */

module aes128_key_register #(
  parameter bit ResetAll = 1'b0
) (
  input  logic        clk_i,
  input  logic        rst_ni,
  
  // Key programming interface
  input  logic        key_we_i,      // Key write enable
  input  logic [127:0] key_i,        // Key input
  
  // Key output to crypto units
  output logic [127:0] key_o,
  output logic         key_valid_o   // Indicates key has been programmed
);

  logic [127:0] key_q;
  logic         key_valid_q;

  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      key_q       <= ResetAll ? '0 : 'x;
      key_valid_q <= 1'b0;
    end else if (key_we_i) begin
      key_q       <= key_i;
      key_valid_q <= 1'b1;
    end
  end

  assign key_o       = key_q;
  assign key_valid_o = key_valid_q;

endmodule