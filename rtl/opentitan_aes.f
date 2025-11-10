
// OpenTitan AES File List
// Include directories
+incdir+rtl/opentitan
+incdir+rtl/opentitan/aes
+incdir+rtl/opentitan/prim

// Package files (order matters!)
rtl/opentitan/edn_pkg.sv
rtl/opentitan/lc_ctrl_pkg.sv
rtl/opentitan/keymgr_pkg.sv
rtl/opentitan/prim/prim_pkg.sv
rtl/opentitan/aes/aes_pkg.sv
rtl/opentitan/aes/aes_reg_pkg.sv

// Primitive files
rtl/opentitan/prim/prim_assert.sv
rtl/opentitan/prim/prim_flop.sv
rtl/opentitan/prim/prim_flop_2sync.sv
rtl/opentitan/prim/prim_buf.sv
rtl/opentitan/prim/prim_and2.sv
rtl/opentitan/prim/prim_xor2.sv
rtl/opentitan/prim/prim_sec_anchor.sv
rtl/opentitan/prim/prim_subreg.sv

// AES core files
rtl/opentitan/aes/aes_sbox_lut.sv
rtl/opentitan/aes/aes_sbox.sv
rtl/opentitan/aes/aes_sub_bytes.sv
rtl/opentitan/aes/aes_shift_rows.sv
rtl/opentitan/aes/aes_mix_single_column.sv
rtl/opentitan/aes/aes_mix_columns.sv
rtl/opentitan/aes/aes_key_expand.sv
rtl/opentitan/aes/aes_cipher_control.sv
rtl/opentitan/aes/aes_cipher_core.sv

// Wrapper (you need to add this file separately)
rtl/aes128_cipher_ot_wrapper.sv
