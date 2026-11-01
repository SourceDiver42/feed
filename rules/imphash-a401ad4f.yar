rule Sightlines_imphash_a401ad4f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a401ad4f"
        date = "2026-10-20"
        campaign = "imphash-a401ad4f"
        family = ""
        hash = "188a79e5b0aeb2656c15fc167bac923b94752b98996f1981e95c173729ce7a0f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a401ad4f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "%sone%08X.tmp" ascii
        $s1 = "lstrcpyA" ascii
        $s2 = "ARIESONE" ascii
        $s3 = "lstrcatA" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 4 of them
}
