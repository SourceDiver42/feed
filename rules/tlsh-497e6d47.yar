rule Sightlines_tlsh_497e6d47_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-497e6d47"
        date = "2026-10-30"
        campaign = "tlsh-497e6d47"
        family = ""
        hash = "5c8da79724eb992eb76483d5d9e54d6c4c12e21125e70ec1a6b87268603b81e8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-497e6d47.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s1 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s2 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s4 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s5 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
        $s6 = "failed to reconstruct packet after VERDICT_MODIFY" ascii
        $s7 = " --lua-desync=<functon>[:param1=val1[:param2=val2]]" ascii
        $s8 = "; override fwmark for generated packets. default = 0x%08X (%u)" ascii
        $s9 = "unbinding existing nf_queue handler for AF_INET6 (if any)" ascii
        $s10 = "desync profile search for %s ip1=%s ip2=%s port=%u icmp=%u:%u l7proto=%s ssid='%s' mark=0x%08X hostn" ascii
        $s11 = "QUIC initial contains CRYPTO with full fragment coverage" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1382032 and 12 of them
}
