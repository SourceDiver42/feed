rule Sightlines_mutex_409c8fd9_winosstager
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign mutex-409c8fd9"
        date = "2026-10-31"
        campaign = "mutex-409c8fd9"
        family = "winosstager"
        hash = "3f3e8aed1a5bb4c86420bc0157df63f6c4ece52725dd8e5684155cbb57d6f012"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/mutex-409c8fd9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "nolmjkhifgdebc`a~" ascii
        $s1 = "NtQueryObject" ascii
        $s2 = "WINSPOOL.DRV" ascii
        $s3 = "RegEnumKeyW" ascii
        $s4 = "MSIMG32.dll" ascii
        $s5 = "joyGetPos" ascii
        $s6 = "nf~vNF^V" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 20505600 and 7 of them
}
