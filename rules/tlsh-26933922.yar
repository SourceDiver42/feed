rule Sightlines_tlsh_26933922_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-26933922"
        date = "2026-10-30"
        campaign = "tlsh-26933922"
        family = ""
        hash = "1bd3bbf143f960fbd926dd4d48e2fadd04011274395090384ff97d229f20ede3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-26933922.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d.googlesource.com/toolchain/llvm-project d8003a456d14a3deb8054cdaa529ffbf02d9b262)" ascii
        $s1 = "Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4 (https://androi" ascii
        $s2 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s3 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s4 = "libunwind: malformed DW_CFA_GNU_negative_offset_extended DWARF unwind, reg too big" ascii
        $s5 = "libunwind: malformed DW_CFA_val_offset DWARF unwind, reg (%llu) out of range" ascii
        $s6 = "libunwind: malformed DW_CFA_val_expression DWARF unwind, reg too big" ascii
        $s7 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s8 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s9 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s10 = "libunwind: malformed DW_CFA_offset DWARF unwind, reg (%llu) out of range" ascii
        $s11 = "libunwind: malformed DW_CFA_val_offset_sf DWARF unwind, reg too big" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1232216 and 12 of them
}
