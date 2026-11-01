rule Sightlines_tlsh_2e6d78d4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2e6d78d4"
        date = "2026-11-01"
        campaign = "tlsh-2e6d78d4"
        family = ""
        hash = "359298d5e70b0bdcd2d9bed785ce95f8fd84674ac7883af4de3487b0ed1ca081"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2e6d78d4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "L$v8\\$vt*8Y" ascii
        $s1 = "T$v8\\$vt?8Z" ascii
        $s2 = "t$XfD9+t#" ascii
        $s3 = "tzfD9 ttH" ascii
        $s4 = "tZ;|$0tM" ascii
        $s5 = "H9D$HtTH" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 6 of them
}
