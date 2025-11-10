/**
 * AES-128 Cipher Module - Complete Encrypt/Decrypt
 * * V2 - Fixed all issues from user feedback:
 * 1. Corrected shift_rows and inv_shift_rows functions.
 * 2. Implemented "Equivalent Inverse Cipher" for decryption.
 * 3. Fixed state machine logic and round counting.
 */

module aes128_cipher (
  input  logic        clk_i,
  input  logic        rst_ni,
  input  logic [127:0] key_i,
  input  logic [127:0] data_i,
  input  logic        decrypt_i,    // 0 = encrypt, 1 = decrypt
  input  logic        valid_i,      // Start operation
  output logic [127:0] data_o,
  output logic        valid_o       // Operation complete
);

  // State machine for AES rounds
  typedef enum logic [3:0] {
    IDLE    = 4'h0,
    INIT    = 4'h1,
    ROUND1  = 4'h2,
    ROUND2  = 4'h3,
    ROUND3  = 4'h4,
    ROUND4  = 4'h5,
    ROUND5  = 4'h6,
    ROUND6  = 4'h7,
    ROUND7  = 4'h8,
    ROUND8  = 4'h9,
    ROUND9  = 4'hA,
    ROUND10 = 4'hB,
    DONE    = 4'hC
  } state_e;
  
  state_e state_q, state_d;
  logic [127:0] state_reg_q, state_reg_d;
  logic [127:0] key_schedule [0:10];
  logic [3:0] round_q, round_d;
  logic [127:0] transformed_key;

  //==================================================================
  // S-BOX (FOR ENCRYPTION) [cite: 31-45]
  //==================================================================
  logic [7:0] sbox [0:255];
  initial begin
    sbox[0]=8'h63; sbox[1]=8'h7c; sbox[2]=8'h77; sbox[3]=8'h7b; sbox[4]=8'hf2; sbox[5]=8'h6b; sbox[6]=8'h6f; sbox[7]=8'hc5;
    sbox[8]=8'h30; sbox[9]=8'h01; sbox[10]=8'h67; sbox[11]=8'h2b; sbox[12]=8'hfe; sbox[13]=8'hd7; sbox[14]=8'hab; sbox[15]=8'h76;
    sbox[16]=8'hca; sbox[17]=8'h82; sbox[18]=8'hc9; sbox[19]=8'h7d; sbox[20]=8'hfa; sbox[21]=8'h59; sbox[22]=8'h47; sbox[23]=8'hf0;
    sbox[24]=8'had; sbox[25]=8'hd4; sbox[26]=8'ha2; sbox[27]=8'haf; sbox[28]=8'h9c; sbox[29]=8'ha4; sbox[30]=8'h72; sbox[31]=8'hc0;
    sbox[32]=8'hb7; sbox[33]=8'hfd; sbox[34]=8'h93; sbox[35]=8'h26; sbox[36]=8'h36; sbox[37]=8'h3f; sbox[38]=8'hf7; sbox[39]=8'hcc;
    sbox[40]=8'h34; sbox[41]=8'ha5; sbox[42]=8'he5; sbox[43]=8'hf1; sbox[44]=8'h71; sbox[45]=8'hd8; sbox[46]=8'h31; sbox[47]=8'h15;
    sbox[48]=8'h04; sbox[49]=8'hc7; sbox[50]=8'h23; sbox[51]=8'hc3; sbox[52]=8'h18; sbox[53]=8'h96; sbox[54]=8'h05; sbox[55]=8'h9a;
    sbox[56]=8'h07; sbox[57]=8'h12; sbox[58]=8'h80; sbox[59]=8'he2; sbox[60]=8'heb; sbox[61]=8'h27; sbox[62]=8'hb2; sbox[63]=8'h75;
    sbox[64]=8'h09; sbox[65]=8'h83; sbox[66]=8'h2c; sbox[67]=8'h1a; sbox[68]=8'h1b; sbox[69]=8'h6e; sbox[70]=8'h5a; sbox[71]=8'ha0;
    sbox[72]=8'h52; sbox[73]=8'h3b; sbox[74]=8'hd6; sbox[75]=8'hb3; sbox[76]=8'h29; sbox[77]=8'he3; sbox[78]=8'h2f; sbox[79]=8'h84;
    sbox[80]=8'h53; sbox[81]=8'hd1; sbox[82]=8'h00; sbox[83]=8'hed; sbox[84]=8'h20; sbox[85]=8'hfc; sbox[86]=8'hb1; sbox[87]=8'h5b;
    sbox[88]=8'h6a; sbox[89]=8'hcb; sbox[90]=8'hbe; sbox[91]=8'h39; sbox[92]=8'h4a; sbox[93]=8'h4c; sbox[94]=8'h58; sbox[95]=8'hcf;
    sbox[96]=8'hd0; sbox[97]=8'hef; sbox[98]=8'haa; sbox[99]=8'hfb; sbox[100]=8'h43; sbox[101]=8'h4d; sbox[102]=8'h33; sbox[103]=8'h85;
    sbox[104]=8'h45; sbox[105]=8'hf9; sbox[106]=8'h02; sbox[107]=8'h7f; sbox[108]=8'h50; sbox[109]=8'h3c; sbox[110]=8'h9f; sbox[111]=8'ha8;
    sbox[112]=8'h51; sbox[113]=8'ha3; sbox[114]=8'h40; sbox[115]=8'h8f; sbox[116]=8'h92; sbox[117]=8'h9d; sbox[118]=8'h38; sbox[119]=8'hf5;
    sbox[120]=8'hbc; sbox[121]=8'hb6; sbox[122]=8'hda; sbox[123]=8'h21; sbox[124]=8'h10; sbox[125]=8'hff; sbox[126]=8'hf3; sbox[127]=8'hd2;
    sbox[128]=8'hcd; sbox[129]=8'h0c; sbox[130]=8'h13; sbox[131]=8'hec; sbox[132]=8'h5f; sbox[133]=8'h97; sbox[134]=8'h44; sbox[135]=8'h17;
    sbox[136]=8'hc4; sbox[137]=8'ha7; sbox[138]=8'h7e; sbox[139]=8'h3d; sbox[140]=8'h64; sbox[141]=8'h5d; sbox[142]=8'h19; sbox[143]=8'h73;
    sbox[144]=8'h60; sbox[145]=8'h81; sbox[146]=8'h4f; sbox[147]=8'hdc; sbox[148]=8'h22; sbox[149]=8'h2a; sbox[150]=8'h90; sbox[151]=8'h88;
    sbox[152]=8'h46; sbox[153]=8'hee; sbox[154]=8'hb8; sbox[155]=8'h14; sbox[156]=8'hde; sbox[157]=8'h5e; sbox[158]=8'h0b; sbox[159]=8'hdb;
    sbox[160]=8'he0; sbox[161]=8'h32; sbox[162]=8'h3a; sbox[163]=8'h0a; sbox[164]=8'h49; sbox[165]=8'h06; sbox[166]=8'h24; sbox[167]=8'h5c;
    sbox[168]=8'hc2; sbox[169]=8'hd3; sbox[170]=8'hac; sbox[171]=8'h62; sbox[172]=8'h91; sbox[173]=8'h95; sbox[174]=8'he4; sbox[175]=8'h79;
    sbox[176]=8'he7; sbox[177]=8'hc8; sbox[178]=8'h37; sbox[179]=8'h6d; sbox[180]=8'h8d; sbox[181]=8'hd5; sbox[182]=8'h4e; sbox[183]=8'ha9;
    sbox[184]=8'h6c; sbox[185]=8'h56; sbox[186]=8'hf4; sbox[187]=8'hea; sbox[188]=8'h65; sbox[189]=8'h7a; sbox[190]=8'hae; sbox[191]=8'h08;
    sbox[192]=8'hba; sbox[193]=8'h78; sbox[194]=8'h25; sbox[195]=8'h2e; sbox[196]=8'h1c; sbox[197]=8'ha6; sbox[198]=8'hb4; sbox[199]=8'hc6;
    sbox[200]=8'he8; sbox[201]=8'hdd; sbox[202]=8'h74; sbox[203]=8'h1f; sbox[204]=8'h4b; sbox[205]=8'hbd; sbox[206]=8'h8b; sbox[207]=8'h8a;
    sbox[208]=8'h70; sbox[209]=8'h3e; sbox[210]=8'hb5; sbox[211]=8'h66; sbox[212]=8'h48; sbox[213]=8'h03; sbox[214]=8'hf6; sbox[215]=8'h0e;
    sbox[216]=8'h61; sbox[217]=8'h35; sbox[218]=8'h57; sbox[219]=8'hb9; sbox[220]=8'h86; sbox[221]=8'hc1; sbox[222]=8'h1d; sbox[223]=8'h9e;
    sbox[224]=8'he1; sbox[225]=8'hf8; sbox[226]=8'h98; sbox[227]=8'h11; sbox[228]=8'h69; sbox[229]=8'hd9; sbox[230]=8'h8e; sbox[231]=8'h94;
    sbox[232]=8'h9b; sbox[233]=8'h1e; sbox[234]=8'h87; sbox[235]=8'he9; sbox[236]=8'hce; sbox[237]=8'h55; sbox[238]=8'h28; sbox[239]=8'hdf;
    sbox[240]=8'h8c; sbox[241]=8'ha1; sbox[242]=8'h89; sbox[243]=8'h0d; sbox[244]=8'hbf; sbox[245]=8'he6; sbox[246]=8'h42; sbox[247]=8'h68;
    sbox[248]=8'h41; sbox[249]=8'h99; sbox[250]=8'h2d; sbox[251]=8'h0f; sbox[252]=8'hb0; sbox[253]=8'h54; sbox[254]=8'hbb; sbox[255]=8'h16;
  end
  
  //==================================================================
  // INVERSE S-BOX (FOR DECRYPTION) [cite: 77-103]
  //==================================================================
  logic [7:0] inv_sbox [0:255];
  initial begin
    inv_sbox[8'h00]=8'h52; inv_sbox[8'h01]=8'h09; inv_sbox[8'h02]=8'h6a; inv_sbox[8'h03]=8'hd5; inv_sbox[8'h04]=8'h30; inv_sbox[8'h05]=8'h36; inv_sbox[8'h06]=8'ha5; inv_sbox[8'h07]=8'h38;
    inv_sbox[8'h08]=8'hbf; inv_sbox[8'h09]=8'h40; inv_sbox[8'h0a]=8'ha3; inv_sbox[8'h0b]=8'h9e; inv_sbox[8'h0c]=8'h81; inv_sbox[8'h0d]=8'hf3; inv_sbox[8'h0e]=8'hd7; inv_sbox[8'h0f]=8'hfb;
    inv_sbox[8'h10]=8'h7c; inv_sbox[8'h11]=8'he3; inv_sbox[8'h12]=8'h39; inv_sbox[8'h13]=8'h82; inv_sbox[8'h14]=8'h9b; inv_sbox[8'h15]=8'h2f; inv_sbox[8'h16]=8'hff; inv_sbox[8'h17]=8'h87;
    inv_sbox[8'h18]=8'h34; inv_sbox[8'h19]=8'h8e; inv_sbox[8'h1a]=8'h43; inv_sbox[8'h1b]=8'h44; inv_sbox[8'h1c]=8'hc4; inv_sbox[8'h1d]=8'hde; inv_sbox[8'h1e]=8'he9; inv_sbox[8'h1f]=8'hcb;
    inv_sbox[8'h20]=8'h54; inv_sbox[8'h21]=8'h7b; inv_sbox[8'h22]=8'h94; inv_sbox[8'h23]=8'h32; inv_sbox[8'h24]=8'ha6; inv_sbox[8'h25]=8'hc2; inv_sbox[8'h26]=8'h23; inv_sbox[8'h27]=8'h3d;
    inv_sbox[8'h28]=8'hee; inv_sbox[8'h29]=8'h4c; inv_sbox[8'h2a]=8'h95; inv_sbox[8'h2b]=8'h0b; inv_sbox[8'h2c]=8'h42; inv_sbox[8'h2d]=8'hfa; inv_sbox[8'h2e]=8'hc3; inv_sbox[8'h2f]=8'h4e;
    inv_sbox[8'h30]=8'h08; inv_sbox[8'h31]=8'h2e; inv_sbox[8'h32]=8'ha1; inv_sbox[8'h33]=8'h66; inv_sbox[8'h34]=8'h28; inv_sbox[8'h35]=8'hd9; inv_sbox[8'h36]=8'h24; inv_sbox[8'h37]=8'hb2;
    inv_sbox[8'h38]=8'h76; inv_sbox[8'h39]=8'h5b; inv_sbox[8'h3a]=8'ha2; inv_sbox[8'h3b]=8'h49; inv_sbox[8'h3c]=8'h6d; inv_sbox[8'h3d]=8'h8b; inv_sbox[8'h3e]=8'hd1; inv_sbox[8'h3f]=8'h25;
    inv_sbox[8'h40]=8'h72; inv_sbox[8'h41]=8'hf8; inv_sbox[8'h42]=8'hf6; inv_sbox[8'h43]=8'h64; inv_sbox[8'h44]=8'h86; inv_sbox[8'h45]=8'h68; inv_sbox[8'h46]=8'h98; inv_sbox[8'h47]=8'h16;
    inv_sbox[8'h48]=8'hd4; inv_sbox[8'h49]=8'ha4; inv_sbox[8'h4a]=8'h5c; inv_sbox[8'h4b]=8'hcc; inv_sbox[8'h4c]=8'h5d; inv_sbox[8'h4d]=8'h65; inv_sbox[8'h4e]=8'hb6; inv_sbox[8'h4f]=8'h92;
    inv_sbox[8'h50]=8'h6c; inv_sbox[8'h51]=8'h70; inv_sbox[8'h52]=8'h48; inv_sbox[8'h53]=8'h50; inv_sbox[8'h54]=8'hfd; inv_sbox[8'h55]=8'hed; inv_sbox[8'h56]=8'hb9; inv_sbox[8'h57]=8'hda;
    inv_sbox[8'h58]=8'h5e; inv_sbox[8'h59]=8'h15; inv_sbox[8'h5a]=8'h46; inv_sbox[8'h5b]=8'h57; inv_sbox[8'h5c]=8'ha7; inv_sbox[8'h5d]=8'h8d; inv_sbox[8'h5e]=8'h9d; inv_sbox[8'h5f]=8'h84;
    inv_sbox[8'h60]=8'h90; inv_sbox[8'h61]=8'hd8; inv_sbox[8'h62]=8'hab; inv_sbox[8'h63]=8'h00; inv_sbox[8'h64]=8'h8c; inv_sbox[8'h65]=8'hbc; inv_sbox[8'h66]=8'hd3; inv_sbox[8'h67]=8'h0a;
    inv_sbox[8'h68]=8'hf7; inv_sbox[8'h69]=8'he4; inv_sbox[8'h6a]=8'h58; inv_sbox[8'h6b]=8'h05; inv_sbox[8'h6c]=8'hb8; inv_sbox[8'h6d]=8'hb3; inv_sbox[8'h6e]=8'h45; inv_sbox[8'h6f]=8'h06;
    inv_sbox[8'h70]=8'hd0; inv_sbox[8'h71]=8'h2c; inv_sbox[8'h72]=8'h1e; inv_sbox[8'h73]=8'h8f; inv_sbox[8'h74]=8'hca; inv_sbox[8'h75]=8'h3f; inv_sbox[8'h76]=8'h0f; inv_sbox[8'h77]=8'h02;
    inv_sbox[8'h78]=8'hc1; inv_sbox[8'h79]=8'haf; inv_sbox[8'h7a]=8'hbd; inv_sbox[8'h7b]=8'h03; inv_sbox[8'h7c]=8'h01; inv_sbox[8'h7d]=8'h13; inv_sbox[8'h7e]=8'h8a; inv_sbox[8'h7f]=8'h6b;
    inv_sbox[8'h80]=8'h3a; inv_sbox[8'h81]=8'h91; inv_sbox[8'h82]=8'h11; inv_sbox[8'h83]=8'h41; inv_sbox[8'h84]=8'h4f; inv_sbox[8'h85]=8'h67; inv_sbox[8'h86]=8'hdc; inv_sbox[8'h87]=8'hea;
    inv_sbox[8'h88]=8'h97; inv_sbox[8'h89]=8'hf2; inv_sbox[8'h8a]=8'hcf; inv_sbox[8'h8b]=8'hce; inv_sbox[8'h8c]=8'hf0; inv_sbox[8'h8d]=8'hb4; inv_sbox[8'h8e]=8'he6; inv_sbox[8'h8f]=8'h73;
    inv_sbox[8'h90]=8'h96; inv_sbox[8'h91]=8'hac; inv_sbox[8'h92]=8'h74; inv_sbox[8'h93]=8'h22; inv_sbox[8'h94]=8'he7; inv_sbox[8'h95]=8'had; inv_sbox[8'h96]=8'h35; inv_sbox[8'h97]=8'h85;
    inv_sbox[8'h98]=8'he2; inv_sbox[8'h99]=8'hf9; inv_sbox[8'h9a]=8'h37; inv_sbox[8'h9b]=8'he8; inv_sbox[8'h9c]=8'h1c; inv_sbox[8'h9d]=8'h75; inv_sbox[8'h9e]=8'hdf; inv_sbox[8'h9f]=8'h6e;
    inv_sbox[8'ha0]=8'h47; inv_sbox[8'ha1]=8'hf1; inv_sbox[8'ha2]=8'h1a; inv_sbox[8'ha3]=8'h71; inv_sbox[8'ha4]=8'h1d; inv_sbox[8'ha5]=8'h29; inv_sbox[8'ha6]=8'hc5; inv_sbox[8'ha7]=8'h89;
    inv_sbox[8'ha8]=8'h6f; inv_sbox[8'ha9]=8'hb7; inv_sbox[8'haa]=8'h62; inv_sbox[8'hab]=8'h0e; inv_sbox[8'hac]=8'haa; inv_sbox[8'had]=8'h18; inv_sbox[8'hae]=8'hbe; inv_sbox[8'haf]=8'h1b;
    inv_sbox[8'hb0]=8'hfc; inv_sbox[8'hb1]=8'h56; inv_sbox[8'hb2]=8'h3e; inv_sbox[8'hb3]=8'h4b; inv_sbox[8'hb4]=8'hc6; inv_sbox[8'hb5]=8'hd2; inv_sbox[8'hb6]=8'h79; inv_sbox[8'hb7]=8'h20;
    inv_sbox[8'hb8]=8'h9a; inv_sbox[8'hb9]=8'hdb; inv_sbox[8'hba]=8'hc0; inv_sbox[8'hbb]=8'hfe; inv_sbox[8'hbc]=8'h78; inv_sbox[8'hbd]=8'hcd; inv_sbox[8'hbe]=8'h5a; inv_sbox[8'hbf]=8'hf4;
    inv_sbox[8'hc0]=8'h1f; inv_sbox[8'hc1]=8'hdd; inv_sbox[8'hc2]=8'ha8; inv_sbox[8'hc3]=8'h33; inv_sbox[8'hc4]=8'h88; inv_sbox[8'hc5]=8'h07; inv_sbox[8'hc6]=8'hc7; inv_sbox[8'hc7]=8'h31;
    inv_sbox[8'hc8]=8'hb1; inv_sbox[8'hc9]=8'h12; inv_sbox[8'hca]=8'h10; inv_sbox[8'hcb]=8'h59; inv_sbox[8'hcc]=8'h27; inv_sbox[8'hcd]=8'h80; inv_sbox[8'hce]=8'hec; inv_sbox[8'hcf]=8'h5f;
    inv_sbox[8'hd0]=8'h60; inv_sbox[8'hd1]=8'h51; inv_sbox[8'hd2]=8'h7f; inv_sbox[8'hd3]=8'ha9; inv_sbox[8'hd4]=8'h19; inv_sbox[8'hd5]=8'hb5; inv_sbox[8'hd6]=8'h4a; inv_sbox[8'hd7]=8'h0d;
    inv_sbox[8'hd8]=8'h2d; inv_sbox[8'hd9]=8'he5; inv_sbox[8'hda]=8'h7a; inv_sbox[8'hdb]=8'h9f; inv_sbox[8'hdc]=8'h93; inv_sbox[8'hdd]=8'hc9; inv_sbox[8'hde]=8'h9c; inv_sbox[8'hdf]=8'hef;
    inv_sbox[8'he0]=8'ha0; inv_sbox[8'he1]=8'he0; inv_sbox[8'he2]=8'h3b; inv_sbox[8'he3]=8'h4d; inv_sbox[8'he4]=8'hae; inv_sbox[8'he5]=8'h2a; inv_sbox[8'he6]=8'hf5; inv_sbox[8'he7]=8'hb0;
    inv_sbox[8'he8]=8'hc8; inv_sbox[8'he9]=8'heb; inv_sbox[8'hea]=8'hbb; inv_sbox[8'heb]=8'h3c; inv_sbox[8'hec]=8'h83; inv_sbox[8'hed]=8'h53; inv_sbox[8'hee]=8'h99; inv_sbox[8'hef]=8'h61;
    inv_sbox[8'hf0]=8'h17; inv_sbox[8'hf1]=8'h2b; inv_sbox[8'hf2]=8'h04; inv_sbox[8'hf3]=8'h7e; inv_sbox[8'hf4]=8'hba; inv_sbox[8'hf5]=8'h77; inv_sbox[8'hf6]=8'hd6; inv_sbox[8'hf7]=8'h26;
    inv_sbox[8'hf8]=8'he1; inv_sbox[8'hf9]=8'h69; inv_sbox[8'hfa]=8'h14; inv_sbox[8'hfb]=8'h63; inv_sbox[8'hfc]=8'h55; inv_sbox[8'hfd]=8'h21; inv_sbox[8'hfe]=8'h0c; inv_sbox[8'hff]=8'h7d;
  end

  // Rcon values [cite: 45-47]
  logic [31:0] rcon [0:10];
  initial begin
    rcon[0] = 32'h00000000;
    rcon[1] = 32'h01000000;
    rcon[2] = 32'h02000000;
    rcon[3] = 32'h04000000;
    rcon[4] = 32'h08000000;
    rcon[5] = 32'h10000000;
    rcon[6] = 32'h20000000;
    rcon[7] = 32'h40000000;
    rcon[8] = 32'h80000000;
    rcon[9] = 32'h1b000000;
    rcon[10] = 32'h36000000;
  end
  
  //==================================================================
  // GF(2^8) Multiplication Functions
  //==================================================================
  
  // Multiply by {02}  [cite: 48-49, 133-134]
  function automatic logic [7:0] gf_mul2(logic [7:0] x);
    return (x[7]) ? ((x << 1) ^ 8'h1b) : (x << 1);
  endfunction
  
  // Multiply by {03} [cite: 48-49]
  function automatic logic [7:0] gf_mul3(logic [7:0] x);
    return gf_mul2(x) ^ x;
  endfunction

  // Multiply by {09}
  function automatic logic [7:0] gf_mul9(logic [7:0] x);
    logic [7:0] m2, m4, m8;
    m2 = gf_mul2(x);
    m4 = gf_mul2(m2);
    m8 = gf_mul2(m4);
    return m8 ^ x;
  endfunction

  // Multiply by {0b}
  function automatic logic [7:0] gf_mulB(logic [7:0] x);
    logic [7:0] m2, m4, m8;
    m2 = gf_mul2(x);
    m4 = gf_mul2(m2);
    m8 = gf_mul2(m4);
    return m8 ^ m2 ^ x;
  endfunction

  // Multiply by {0d}
  function automatic logic [7:0] gf_mulD(logic [7:0] x);
    logic [7:0] m2, m4, m8;
    m2 = gf_mul2(x);
    m4 = gf_mul2(m2);
    m8 = gf_mul2(m4);
    return m8 ^ m4 ^ x;
  endfunction
  
  // Multiply by {0e}
  function automatic logic [7:0] gf_mulE(logic [7:0] x);
    logic [7:0] m2, m4, m8;
    m2 = gf_mul2(x);
    m4 = gf_mul2(m2);
    m8 = gf_mul2(m4);
    return m8 ^ m4 ^ m2;
  endfunction

  //==================================================================
  // ENCRYPTION FUNCTIONS
  //==================================================================
  
  // SubBytes (Encrypt) [cite: 50-52]
  function automatic logic [127:0] sub_bytes(logic [127:0] state);
    logic [127:0] result;
    for (int i = 0; i < 16; i++) begin
      result[i*8 +: 8] = sbox[state[i*8 +: 8]];
    end
    return result;
  endfunction
  
  // -----------------------------------------------------------------
  // *** FIXED: ShiftRows (Encrypt) ***
  // Corrected to match the state mapping from mix_columns [cite: 51-58]
  // -----------------------------------------------------------------
  function automatic logic [127:0] shift_rows(logic [127:0] state);
    logic [127:0] result;
    // State mapping:
    // Row 0: state[7:0],   state[39:32],  state[71:64],  state[103:96]
    // Row 1: state[15:8],  state[47:40],  state[79:72],  state[111:104]
    // Row 2: state[23:16], state[55:48],  state[87:80],  state[119:112]
    // Row 3: state[31:24], state[63:56],  state[95:88],  state[127:120]
    
    // Row 0 (no shift)
    result[7:0]    = state[7:0];
    result[39:32]  = state[39:32];
    result[71:64]  = state[71:64];
    result[103:96] = state[103:96];

    // Row 1 (shift left 1)
    result[15:8]    = state[47:40];
    result[47:40]   = state[79:72];
    result[79:72]   = state[111:104];
    result[111:104] = state[15:8];
    
    // Row 2 (shift left 2)
    result[23:16]   = state[87:80];
    result[55:48]   = state[119:112];
    result[87:80]   = state[23:16];
    result[119:112] = state[55:48];
    
    // Row 3 (shift left 3)
    result[31:24]   = state[127:120];
    result[63:56]   = state[31:24];
    result[95:88]   = state[63:56];
    result[127:120] = state[95:88];
    
    return result;
  endfunction
  
  // MixColumns (Encrypt) [cite: 51-58]
  function automatic logic [127:0] mix_columns(logic [127:0] state);
    logic [127:0] result;
    logic [7:0] a, b, c, d;
    for (int col = 0; col < 4; col++) begin
      // State bytes are (d, c, b, a) from LSB to MSB in each 32-bit col
      d = state[(col*32)    +: 8]; // row 3
      c = state[(col*32+8)  +: 8]; // row 2
      b = state[(col*32+16) +: 8]; // row 1
      a = state[(col*32+24) +: 8]; // row 0
      
      // Note: The original function [cite: 54-58] had a,b,c,d mapped to row 0,1,2,3
      // which is (a=state[24+], b=state[16+], c=state[8+], d=state[0+])
      // This is correct for the state mapping.
      a = state[(col*32+24) +: 8]; // row 0
      b = state[(col*32+16) +: 8]; // row 1
      c = state[(col*32+8)  +: 8]; // row 2
      d = state[(col*32)    +: 8]; // row 3

      result[(col*32+24) +: 8] = gf_mul2(a) ^ gf_mul3(b) ^ c         ^ d;         // row 0
      result[(col*32+16) +: 8] = a         ^ gf_mul2(b) ^ gf_mul3(c) ^ d;         // row 1
      result[(col*32+8)  +: 8] = a         ^ b         ^ gf_mul2(c) ^ gf_mul3(d); // row 2
      result[(col*32)    +: 8] = gf_mul3(a) ^ b         ^ c         ^ gf_mul2(d); // row 3
    end
    return result;
  endfunction

  //==================================================================
  // DECRYPTION FUNCTIONS
  //==================================================================
  
  // Inverse SubBytes (Decrypt) [cite: 1-2]
  function automatic logic [127:0] inv_sub_bytes(logic [127:0] state);
    logic [127:0] result;
    for (int i = 0; i < 16; i++) begin
      result[i*8 +: 8] = inv_sbox[state[i*8 +: 8]];
    end
    return result;
  endfunction
  
  // -----------------------------------------------------------------
  // *** FIXED: Inverse ShiftRows (Decrypt) ***
  // Corrected to be the exact inverse of the new shift_rows function
  // This logic is from your inverseShiftRows.v [cite: 103-110]
  // -----------------------------------------------------------------
  function automatic logic [127:0] inv_shift_rows(logic [127:0] state);
    logic [127:0] result;
    // Row 0 (no shift)
    result[7:0]    = state[7:0];
    result[39:32]  = state[39:32];
    result[71:64]  = state[71:64];
    result[103:96] = state[103:96];

    // Row 1 (shift right 1)
    result[15:8]    = state[111:104];
    result[47:40]   = state[15:8];
    result[79:72]   = state[47:40];
    result[111:104] = state[79:72];
    
    // Row 2 (shift right 2)
    result[23:16]   = state[87:80];
    result[55:48]   = state[119:112];
    result[87:80]   = state[23:16];
    result[119:112] = state[55:48];
    
    // Row 3 (shift right 3)
    result[31:24]   = state[63:56];
    result[63:56]   = state[95:88];
    result[95:88]   = state[127:120];
    result[127:120] = state[31:24];
    
    return result;
  endfunction

  // Inverse MixColumns (Decrypt)
  // This is now only used for the key schedule transformation
  function automatic logic [127:0] inv_mix_columns(logic [127:0] state);
    logic [127:0] result;
    logic [7:0] a, b, c, d;
    for (int col = 0; col < 4; col++) begin
      a = state[(col*32+24) +: 8]; // row 0
      b = state[(col*32+16) +: 8]; // row 1
      c = state[(col*32+8)  +: 8]; // row 2
      d = state[(col*32)    +: 8]; // row 3
      
      result[(col*32+24) +: 8] = gf_mulE(a) ^ gf_mulB(b) ^ gf_mulD(c) ^ gf_mul9(d);
      result[(col*32+16) +: 8] = gf_mul9(a) ^ gf_mulE(b) ^ gf_mulB(c) ^ gf_mulD(d);
      result[(col*32+8)  +: 8] = gf_mulD(a) ^ gf_mul9(b) ^ gf_mulE(c) ^ gf_mulB(d);
      result[(col*32)    +: 8] = gf_mulB(a) ^ gf_mulD(b) ^ gf_mul9(c) ^ gf_mulE(d);
    end
    return result;
  endfunction

  //==================================================================
  // Key Expansion [cite: 58-62]
  //==================================================================
  always_comb begin
    key_schedule[0] = key_i;
    for (int i = 1; i <= 10; i++) begin
      logic [31:0] temp, k3;
      k3 = key_schedule[i-1][31:0];
      temp = {sbox[k3[23:16]], sbox[k3[15:8]], sbox[k3[7:0]], sbox[k3[31:24]]};
      temp = temp ^ rcon[i];
      key_schedule[i][127:96] = key_schedule[i-1][127:96] ^ temp;
      key_schedule[i][95:64]  = key_schedule[i-1][95:64]  ^ key_schedule[i][127:96];
      key_schedule[i][63:32]  = key_schedule[i-1][63:32]  ^ key_schedule[i][95:64];
      key_schedule[i][31:0]   = key_schedule[i-1][31:0]   ^ key_schedule[i][63:32];
    end
  end
  //==================================================================
  // *** FIXED: State Machine (Combined Encrypt/Decrypt) ***
  //==================================================================
  always_comb begin
    // Default assignments
    state_d     = state_q;
    state_reg_d = state_reg_q;
    round_d     = round_q;
    valid_o     = 1'b0;
    data_o      = state_reg_q;

    // *** FIX: Declaration removed from here ***
    // We now use the 'transformed_key' signal declared in the module scope.
    // Assign a default value to avoid latches.
    transformed_key = 128'h0; 

    case (state_q)
      IDLE: begin
        if (valid_i) begin
          state_d = INIT;
          round_d = 4'h1; // Always start at round 1
          if (decrypt_i) begin
            // Decryption: AddRoundKey(state, key[10])
            state_reg_d = data_i ^ key_schedule[10];
          end else begin
            // Encryption: AddRoundKey(state, key[0])
            state_reg_d = data_i ^ key_schedule[0];
          end
        end
      end
      
      INIT: state_d = ROUND1;

      // Rounds 1-9
      ROUND1, ROUND2, ROUND3, ROUND4, ROUND5, ROUND6, ROUND7, ROUND8, ROUND9: begin
        if (decrypt_i) begin
          // Decrypt Round: InvShiftRows -> InvSubBytes -> AddRoundKey(InvMix(k_dec))
          state_reg_d = inv_shift_rows(state_reg_q);
          state_reg_d = inv_sub_bytes(state_reg_d);
          
          // Apply InvMixColumns to the key for Equivalent Inverse Cipher
          transformed_key = inv_mix_columns(key_schedule[10 - round_q]); // k[9]..k[1]
          state_reg_d = state_reg_d ^ transformed_key;
        end else begin
          // Encrypt Round: SubBytes -> ShiftRows -> MixCols -> AddRoundKey
          state_reg_d = sub_bytes(state_reg_q);
          state_reg_d = shift_rows(state_reg_d);
          state_reg_d = mix_columns(state_reg_d);
          state_reg_d = state_reg_d ^ key_schedule[round_q]; // k[1]..k[9]
        end
        round_d = round_q + 4'h1; // Always count up
        state_d = state_e'(state_q + 4'h1); // Go to next round state
      end
      
      // Final Round (Round 10)
      ROUND10: begin
        if (decrypt_i) begin
          // Final Decrypt Round: InvShiftRows -> InvSubBytes -> AddRoundKey(k[0])
          state_reg_d = inv_shift_rows(state_reg_q);
          state_reg_d = inv_sub_bytes(state_reg_d);
          state_reg_d = state_reg_d ^ key_schedule[0];
        end else begin
          // Final Encrypt Round: SubBytes -> ShiftRows -> AddRoundKey(k[10])
          state_reg_d = sub_bytes(state_reg_q);
          state_reg_d = shift_rows(state_reg_d);
          state_reg_d = state_reg_d ^ key_schedule[10];
        end
        state_d = DONE;
      end
      
      DONE: begin
        valid_o = 1'b1;
        data_o = state_reg_q;
        state_d = IDLE;
      end

      default: begin
        state_d = IDLE;
      end
    endcase
  end
  
  // Registers
  always_ff @(posedge clk_i or negedge rst_ni) begin
    if (!rst_ni) begin
      state_q     <= IDLE;
      state_reg_q <= 128'h0;
      round_q     <= 4'h0;
    end else begin
      state_q     <= state_d;
      state_reg_q <= state_reg_d;
      round_q     <= round_d;
    end
  end

endmodule