rule Sightlines_tlsh_50e572dc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-50e572dc"
        date = "2026-10-30"
        campaign = "tlsh-50e572dc"
        family = ""
        hash = "0de2ed09e979de3ac6f4b9fe9615ef3891182d69ceeca4fbbc874857ba02f093"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-50e572dc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ%||EcECExEXEyEYOdOeOHOIOmOMOSOuOUOVOwOWOy" ascii
        $s1 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s2 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s3 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s4 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s5 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s6 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
        $s7 = "failed to reconstruct packet after VERDICT_MODIFY" ascii
        $s8 = " --lua-desync=<functon>[:param1=val1[:param2=val2]]" ascii
        $s9 = "; override fwmark for generated packets. default = 0x%08X (%u)" ascii
        $s10 = "unbinding existing nf_queue handler for AF_INET6 (if any)" ascii
        $s11 = "desync profile search for %s ip1=%s ip2=%s port=%u icmp=%u:%u l7proto=%s ssid='%s' mark=0x%08X hostn" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1332328 and 11 of them
}
