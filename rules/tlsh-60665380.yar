rule Sightlines_tlsh_60665380_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-60665380"
        date = "2026-11-01"
        campaign = "tlsh-60665380"
        family = ""
        hash = "0d6b4f7558a1b820378140d3a59b25972dfb70d40d5cccacbad56e60bc24fa93"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-60665380.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "IcL$dIcT$`Mct$TL" ascii
        $s1 = "L$8AkL$t&Mc" ascii
        $s2 = "t$0L;p ~kH" ascii
        $s3 = "D$`H9D$huGH" ascii
        $s4 = "d$XL;d$`tTL" ascii
        $s5 = "4$L9p s\\H" ascii
        $s6 = "AUATUSRH9" ascii
        $s7 = "D$XH9D$`u" ascii
        $s8 = "D$`H9D$ht" ascii
        $s9 = "L$ IcL$tH" ascii
        $s10 = "t\"H9S(t%H" ascii
        $s11 = "tFH9w w@H" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
