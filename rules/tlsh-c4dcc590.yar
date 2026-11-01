rule Sightlines_tlsh_c4dcc590_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c4dcc590"
        date = "2026-11-01"
        campaign = "tlsh-c4dcc590"
        family = ""
        hash = "0764dd0eac58c863c3c99ecd8f4f6ad65fb56d135765afe3233e5adc3c3d696c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c4dcc590.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "D$>fD9t$>t" ascii
        $s1 = "D$THcD$LI" ascii
        $s2 = "AWAVAUATUL" ascii
        $s3 = "F H3G I!" ascii
        $s4 = "H9D$(r1H" ascii
        $s5 = "AWAVAUATM" ascii
        $s6 = "D$x3D$01" ascii
        $s7 = "T$0HcE$H" ascii
        $s8 = "3\\$x3l$l" ascii
        $s9 = "L$<9L$Ls" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1081536 and 9 of them
}
