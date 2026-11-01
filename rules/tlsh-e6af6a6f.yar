rule Sightlines_tlsh_e6af6a6f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e6af6a6f"
        date = "2026-11-01"
        campaign = "tlsh-e6af6a6f"
        family = ""
        hash = "27c57e4177730efd7b7c8e3875fdd2c2d45a72c801bd131d617f4228075ebddb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e6af6a6f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s1 = "/etc/config/resolv.conf" ascii
        $s2 = "nd 3expa2-byte k" ascii
        $s3 = "/etc/config/hosts" ascii
        $s4 = ".comment" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 5 of them
}
