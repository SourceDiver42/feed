rule Sightlines_imphash_a2e5f911_remusstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a2e5f911"
        date = "2026-10-21"
        campaign = "imphash-a2e5f911"
        family = "remusstealer"
        hash = "06e8c194b2dfce2771dd27e0b8c029497ca6617e5719297cf39f08007e46ad45"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a2e5f911.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "CreateDesktopW" ascii
        $s1 = "f~}iaa|wH" ascii
        $s2 = "LA@fF;LD" ascii
        $s3 = "L$xL;L$X" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 4 of them
}
