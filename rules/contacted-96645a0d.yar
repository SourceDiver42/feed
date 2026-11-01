rule Sightlines_contacted_96645a0d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-96645a0d"
        date = "2026-10-22"
        campaign = "contacted-96645a0d"
        family = ""
        hash = "24294bb46842f08d3f37989de1f47d0aef9eaffa1fc9eea3ceda173702978641"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-96645a0d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s1 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s2 = "Partial loss of significance (PLOSS)" ascii
        $s3 = "api-ms-win-crt-multibyte-l1-1-0.dll" ascii
        $s4 = "Total loss of significance (TLOSS)" ascii
        $s5 = "Overflow range error (OVERFLOW)" ascii
        $s6 = "Argument domain error (DOMAIN)" ascii
        $s7 = "Argument singularity (SIGN)" ascii
        $s8 = "runtime error %d" ascii
        $s9 = "client32.exe" ascii
        $s10 = ":MZurLcB<B" ascii
        $s11 = "_ismbblead" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12253184 and 12 of them
}
