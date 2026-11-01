rule Sightlines_tlsh_be693fef_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-be693fef"
        date = "2026-10-30"
        campaign = "tlsh-be693fef"
        family = ""
        hash = "17cdeba2d4f714da88a50bd06e3769d2bfe187c07bb84fad8e6c308689f77133"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-be693fef.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz" wide
        $s1 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l" wide
        $s2 = "{7>8cE>kV#)WzH" ascii
        $s3 = "Sn_bC~Ora\\%" ascii
        $s4 = "#GK*5A?^CCM" ascii
        $s5 = "mg99? Yrk63" ascii
        $s6 = "D$0H;D$8s@H" ascii
        $s7 = "D$0H;D$PtKH" ascii
        $s8 = "D$0H;D$XtFH" ascii
        $s9 = "D$0H;D$8s7H" ascii
        $s10 = "D$pH;D$Xs7H" ascii
        $s11 = "??EVU~+vcC" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1490944 and 12 of them
}
