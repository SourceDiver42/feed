rule Sightlines_tlsh_90af4443_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-90af4443"
        date = "2026-11-01"
        campaign = "tlsh-90af4443"
        family = "mirai"
        hash = "0c0295c4b0b1f4d92b0d36bf2f5d8107ff21fb8c13fd0bc84c108462eaa95579"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-90af4443.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s1 = "Accept-Encoding: gzip, deflate" ascii
        $s2 = "/etc/config/resolv.conf" ascii
        $s3 = "Unknown error Success" ascii
        $s4 = "/etc/config/hosts" ascii
        $s5 = "/proc/%d/stat" ascii
        $s6 = "/proc/%d/exe" ascii
        $s7 = "D @N^NuNV" ascii
        $s8 = "L @N^NuNV" ascii
        $s9 = "j @N^NuNV" ascii
        $s10 = " @N^NuNuNV" ascii
        $s11 = "$_N^NuNuNV" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
