rule Sightlines_imphash_9613bd7a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9613bd7a"
        date = "2026-10-23"
        campaign = "imphash-9613bd7a"
        family = ""
        hash = "36c3922133d08c3b05eda761d3d0667000729ec541a2b8c3dba443904bf88da9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-9613bd7a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Mrgpcvkml\"amorngvgf\"qwaagqqdwnn{" ascii
        $s1 = "Dbttrddqb{{n7zxs~q~rs7erp~dcen9" ascii
        $s2 = "`abcdefghijklmno" ascii
        $s3 = "Faejl{jk/fa{`/" ascii
        $s4 = "9!*+UVYZNtuo" ascii
        $s5 = "pTrA)XTrq)\\Uc" ascii
        $s6 = "Xo{excQoo\\\\\\" ascii
        $s7 = "013478=*,T" ascii
        $s8 = "9$*+UYOtu`" ascii
        $s9 = "9|f_QLaC!F" ascii
        $s10 = "Z dXR1>,Q." ascii
        $s11 = "CEVYDVTC^XY" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10848256 and 12 of them
}
