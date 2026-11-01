rule Sightlines_tlsh_3729e6a6_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3729e6a6"
        date = "2026-11-01"
        campaign = "tlsh-3729e6a6"
        family = "mirai"
        hash = "03df0e485f3e3e8388810b650459a92268da897f226c2c5af3331e22498eba99"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3729e6a6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/etc/config/resolv.conf" ascii
        $s1 = "/etc/config/hosts" ascii
        $s2 = "/proc/%d/exe" ascii
        $s3 = "Cx}1Kx}PSxK" ascii
        $s4 = "x}'Kx}j[x8" ascii
        $s5 = "}CX.}CSxN" ascii
        $s6 = "}CSx}e[x" ascii
        $s7 = "}e[x}CSx" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}
