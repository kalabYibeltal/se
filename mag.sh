#!/bin/bash

# Script to update Ibex build files to include OpenTitan AES

echo "Updating Ibex build files for OpenTitan AES..."

# Backup original files
cp ibex_dv.f ibex_dv.f.bak
cp src_files.yml src_files.yml.bak
echo "✓ Created backups"

# Create the OpenTitan section for ibex_dv.f
cat > opentitan_section.txt << 'EOF'

// ============================================================================
// OpenTitan AES Integration
// ============================================================================
+incdir+${PRJ_DIR}/rtl/opentitan
+incdir+${PRJ_DIR}/rtl/opentitan/aes
+incdir+${PRJ_DIR}/rtl/opentitan/prim

// OpenTitan packages (must come first)
${PRJ_DIR}/rtl/opentitan/lc_ctrl_pkg.sv
${PRJ_DIR}/rtl/opentitan/keymgr_pkg.sv
${PRJ_DIR}/rtl/opentitan/prim/prim_pkg.sv
${PRJ_DIR}/rtl/opentitan/prim/prim_util_pkg.sv
${PRJ_DIR}/rtl/opentitan/aes/aes_pkg.sv

// OpenTitan primitives
${PRJ_DIR}/rtl/opentitan/prim/prim_assert.sv
${PRJ_DIR}/rtl/opentitan/prim/prim_generic_flop.sv
${PRJ_DIR}/rtl/opentitan/prim/prim_generic_buf.sv
${PRJ_DIR}/rtl/opentitan/prim/prim_generic_and2.sv
${PRJ_DIR}/rtl/opentitan/prim/prim_generic_xor2.sv
${PRJ_DIR}/rtl/opentitan/prim/prim_flop.sv
${PRJ_DIR}/rtl/opentitan/prim/prim_buf.sv
${PRJ_DIR}/rtl/opentitan/prim/prim_and2.sv
${PRJ_DIR}/rtl/opentitan/prim/prim_xor2.sv

// OpenTitan AES core files
${PRJ_DIR}/rtl/opentitan/aes/aes_sbox_lut.sv
${PRJ_DIR}/rtl/opentitan/aes/aes_sbox.sv
${PRJ_DIR}/rtl/opentitan/aes/aes_sub_bytes.sv
${PRJ_DIR}/rtl/opentitan/aes/aes_shift_rows.sv
${PRJ_DIR}/rtl/opentitan/aes/aes_mix_single_column.sv
${PRJ_DIR}/rtl/opentitan/aes/aes_mix_columns.sv
${PRJ_DIR}/rtl/opentitan/aes/aes_key_expand.sv
${PRJ_DIR}/rtl/opentitan/aes/aes_cipher_control.sv
${PRJ_DIR}/rtl/opentitan/aes/aes_cipher_core.sv
// ============================================================================

EOF

# Insert OpenTitan section into ibex_dv.f after the first prim includes but before ibex_pkg.sv
sed -i '/+incdir+${PRJ_DIR}\/rtl/r opentitan_section.txt' ibex_dv.f

echo "✓ Updated ibex_dv.f"

# Update src_files.yml
# Add include directories
sed -i '/rtl,/a\    rtl/opentitan,\n    rtl/opentitan/aes,\n    rtl/opentitan/prim,' src_files.yml

# Add OpenTitan files after incdirs
sed -i '/files: \[/a\    # OpenTitan AES\n    rtl/opentitan/lc_ctrl_pkg.sv,\n    rtl/opentitan/keymgr_pkg.sv,\n    rtl/opentitan/prim/prim_pkg.sv,\n    rtl/opentitan/prim/prim_util_pkg.sv,\n    rtl/opentitan/aes/aes_pkg.sv,\n    rtl/opentitan/prim/prim_generic_flop.sv,\n    rtl/opentitan/prim/prim_generic_buf.sv,\n    rtl/opentitan/prim/prim_generic_and2.sv,\n    rtl/opentitan/prim/prim_generic_xor2.sv,\n    rtl/opentitan/prim/prim_flop.sv,\n    rtl/opentitan/prim/prim_buf.sv,\n    rtl/opentitan/prim/prim_and2.sv,\n    rtl/opentitan/prim/prim_xor2.sv,\n    rtl/opentitan/aes/aes_sbox_lut.sv,\n    rtl/opentitan/aes/aes_sbox.sv,\n    rtl/opentitan/aes/aes_sub_bytes.sv,\n    rtl/opentitan/aes/aes_shift_rows.sv,\n    rtl/opentitan/aes/aes_mix_single_column.sv,\n    rtl/opentitan/aes/aes_mix_columns.sv,\n    rtl/opentitan/aes/aes_key_expand.sv,\n    rtl/opentitan/aes/aes_cipher_control.sv,\n    rtl/opentitan/aes/aes_cipher_core.sv,' src_files.yml

echo "✓ Updated src_files.yml"

# Clean up
rm opentitan_section.txt

echo ""
echo "✓ All build files updated!"
echo ""
echo "Backups created:"
echo "  - ibex_dv.f.bak"
echo "  - src_files.yml.bak"
echo ""
echo "Next: Rebuild your project"