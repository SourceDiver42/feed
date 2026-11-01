rule Sightlines_tlsh_ddc490cc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ddc490cc"
        date = "2026-10-30"
        campaign = "tlsh-ddc490cc"
        family = ""
        hash = "11c35f7447f64af74865833cbc1f9ce09a388f0a23855d6a2eb4b66bb7bb16d7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ddc490cc.json"
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
        uint32(0) == 0x464C457F and filesize < 1744384 and 12 of them
}
