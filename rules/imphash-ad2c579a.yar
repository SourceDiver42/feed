rule Sightlines_imphash_ad2c579a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-ad2c579a"
        date = "2026-10-24"
        campaign = "imphash-ad2c579a"
        family = ""
        hash = "2cd3f398007642bba90bfa972b3587e75b6729a5b3c6efdaf8bde818c62db194"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-ad2c579a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\SystemRoot\\System32\\" wide
        $s1 = "FileUtility.exe" wide
        $s2 = "t9fD98u3HcH<" ascii
        $s3 = ".FDGS5$Yfll" ascii
        $s4 = "File Utility" wide
        $s5 = "=jcu.^^env" ascii
        $s6 = "0Lo4BJ.}E" ascii
        $s7 = "ZDcQ$Ib}m" ascii
        $s8 = "r8,^e7thc" ascii
        $s9 = "/yB|Rdt8" ascii
        $s10 = "mS8>BQdR" ascii
        $s11 = "p\\h6[^Z0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2885504 and 9 of them
}
