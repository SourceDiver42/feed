rule Sightlines_tlsh_14458f8c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-14458f8c"
        date = "2026-10-30"
        campaign = "tlsh-14458f8c"
        family = ""
        hash = "158efa1360dc715804e3142da684f3bc8a6cd07e84d0f3377c058a18eb029d6f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-14458f8c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s1 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s2 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s3 = "invalid parameter for prefix-length : %s" ascii
        $s4 = "invalid parameter for v4-threshold : %s" ascii
        $s5 = "invalid parameter for v6-threshold : %s" ascii
        $s6 = "GCC: (crosstool-NG 1.28.0) 15.2.0" ascii
        $s7 = " --prefix-length=min[-max]" ascii
        $s8 = "Required key not available" ascii
        $s9 = "Key was rejected by service" ascii
        $s10 = " --v4-threshold=mul/div" ascii
        $s11 = "github version %s (%s)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
