rule Sightlines_tlsh_c189a697_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c189a697"
        date = "2026-11-01"
        campaign = "tlsh-c189a697"
        family = ""
        hash = "2282d0a32e82ea90bc714977a14a1bf24eaccdf35443cd5db4991899713d8248"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c189a697.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion" wide
        $s1 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s2 = "Copyright 2026 Google LLC. All rights reserved." wide
        $s3 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s4 = "SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Environment" wide
        $s5 = "Partial loss of significance (PLOSS)" ascii
        $s6 = "User-Agent: Chrome/131.0.6778.109" wide
        $s7 = "Total loss of significance (TLOSS)" ascii
        $s8 = "Overflow range error (OVERFLOW)" ascii
        $s9 = "Argument domain error (DOMAIN)" ascii
        $s10 = "Argument singularity (SIGN)" ascii
        $s11 = "SOFTWARE\\Google\\Update\\" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
