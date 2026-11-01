rule Sightlines_tlsh_bc91db56_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-bc91db56"
        date = "2026-10-30"
        campaign = "tlsh-bc91db56"
        family = ""
        hash = "24a8ebd1e89943e7f30673660800e8dda773362e78c4ec3b7837d706cdf0c74b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-bc91db56.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s1 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s2 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s3 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s4 = "invalid parameter for prefix-length : %s" ascii
        $s5 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s6 = "invalid parameter for v4-threshold : %s" ascii
        $s7 = "invalid parameter for v6-threshold : %s" ascii
        $s8 = "option doesn't take an argument -- %.*s" ascii
        $s9 = "Partial loss of significance (PLOSS)" ascii
        $s10 = "Total loss of significance (TLOSS)" ascii
        $s11 = "option requires an argument -- %c" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
