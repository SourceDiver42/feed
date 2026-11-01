rule Sightlines_imphash_c165af9d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c165af9d"
        date = "2026-11-01"
        campaign = "imphash-c165af9d"
        family = ""
        hash = "10062101e1bfdf17c465f4354e75b5d21b529fbe9ab9b777a05c70dc5703f0ed"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c165af9d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s1 = "Copyright 2026 Google LLC. All rights reserved." wide
        $s2 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s3 = "\"C:\\Windows\\System32\\nvidia-smi.exe\"" wide
        $s4 = "Partial loss of significance (PLOSS)" ascii
        $s5 = "Total loss of significance (TLOSS)" ascii
        $s6 = "Overflow range error (OVERFLOW)" ascii
        $s7 = "Argument domain error (DOMAIN)" ascii
        $s8 = "Argument singularity (SIGN)" ascii
        $s9 = "Chrome GPU Monitor (x86)" wide
        $s10 = "8MZuCHcP<H" ascii
        $s11 = "__initenv" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
