rule Sightlines_tlsh_c9898c70_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c9898c70"
        date = "2026-11-01"
        campaign = "tlsh-c9898c70"
        family = "mirai"
        hash = "12b1348cba1874f45147201f3e291a7476766fac4a7d4776c287e6bbc2fda1d3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c9898c70.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/etc/config/resolv.conf" ascii
        $s1 = "Unknown error Success" ascii
        $s2 = "/etc/config/hosts" ascii
        $s3 = "/proc/%d/exe" ascii
        $s4 = "D @N^NuNV" ascii
        $s5 = "L @N^NuNV" ascii
        $s6 = "j @N^NuNV" ascii
        $s7 = " @N^NuNuNV" ascii
        $s8 = "$_N^NuNuNV" ascii
        $s9 = " OHWHQHy" ascii
        $s10 = "$N^NuNuNV" ascii
        $s11 = "HN^NuNuNV" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}
