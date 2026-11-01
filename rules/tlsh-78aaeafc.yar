rule Sightlines_tlsh_78aaeafc_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-78aaeafc"
        date = "2026-11-01"
        campaign = "tlsh-78aaeafc"
        family = "mirai"
        hash = "12eca53696eaae812868f83ae6f4231342ae07fad1ea26919184a1b41f606d77"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-78aaeafc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "L3a L3i(L3q0L3y8H" ascii
        $s1 = "L3c L3k(L3s0L3{8H" ascii
        $s2 = "IcL$dIcT$`Mct$TL" ascii
        $s3 = "t[AWAVAUATUSH" ascii
        $s4 = "tSAWAVAUATUSH" ascii
        $s5 = "SUWVATAUAVAWH" ascii
        $s6 = "L$8AkL$t&Mc" ascii
        $s7 = "A;G,u(HcD$" ascii
        $s8 = "t$0L;p ~kH" ascii
        $s9 = "t1H9\\$ v*L" ascii
        $s10 = "BAWAVAUATUSH" ascii
        $s11 = "D$`H9D$huGH" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 6746688 and 9 of them
}
