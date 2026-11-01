rule Sightlines_tlsh_d6b59b57_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d6b59b57"
        date = "2026-10-30"
        campaign = "tlsh-d6b59b57"
        family = ""
        hash = "00b869d11a07cd92f4c93b346e18d1d79f2fa9a22c34ca63dc8ba85b346d921f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d6b59b57.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d.googlesource.com/toolchain/llvm-project d8003a456d14a3deb8054cdaa529ffbf02d9b262)" ascii
        $s1 = "Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4 (https://androi" ascii
        $s2 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s3 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s4 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s5 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s6 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s7 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
        $s8 = "failed to reconstruct packet after VERDICT_MODIFY" ascii
        $s9 = " --lua-desync=<functon>[:param1=val1[:param2=val2]]" ascii
        $s10 = "; override fwmark for generated packets. default = 0x%08X (%u)" ascii
        $s11 = "unbinding existing nf_queue handler for AF_INET6 (if any)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
