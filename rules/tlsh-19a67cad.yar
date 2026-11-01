rule Sightlines_tlsh_19a67cad_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-19a67cad"
        date = "2026-11-01"
        campaign = "tlsh-19a67cad"
        family = ""
        hash = "17214a0040a36ba59b0af19035c80d58710a07544663cd5cc6f5a40fdc5b7625"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-19a67cad.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "AVAUATUSDkG" ascii
        $s1 = "8-sha512H" ascii
        $s2 = "aes256-cH" ascii
        $s3 = "n-group1H" ascii
        $s4 = "AWAVAUATUSL" ascii
        $s5 = "sha2-256H" ascii
        $s6 = "so.preloH" ascii
        $s7 = "D$xPAVAUD" ascii
        $s8 = "diffie-hH" ascii
        $s9 = "hmac-shaH" ascii
        $s10 = "B<H9T$8u" ascii
        $s11 = "Q<H9L$8u" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
