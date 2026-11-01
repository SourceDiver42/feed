rule Sightlines_tlsh_e31b6e4b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e31b6e4b"
        date = "2026-10-30"
        campaign = "tlsh-e31b6e4b"
        family = ""
        hash = "08b68d9cb8c19d8fbc02f39ab180abc82da175c762bcf69b4ddcb1af81ece07c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e31b6e4b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s1 = "GCC: (Realtek RSDK-4.6.4 Build 2002) 4.6.4" ascii
        $s2 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s3 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s4 = "invalid parameter for prefix-length : %s" ascii
        $s5 = "invalid parameter for v4-threshold : %s" ascii
        $s6 = "invalid parameter for v6-threshold : %s" ascii
        $s7 = "Invalid multibyte format string." ascii
        $s8 = " --prefix-length=min[-max]" ascii
        $s9 = "EUQ\\J),HMP.5;VY9=@D'GKN" wide
        $s10 = "npxXoudifFeEgGaACSnmcs[" ascii
        $s11 = "g|GGGGGGGGGGGGGGSYYY*GGGGGGGGGGG_WLsxGGGGGGGGGGGGG_YYWGGGGGGGGGGGGXIZ+_IE_GIUIZYDF" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
