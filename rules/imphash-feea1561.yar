rule Sightlines_imphash_feea1561_revstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-feea1561"
        date = "2026-10-22"
        campaign = "imphash-feea1561"
        family = "revstealer"
        hash = "0cb21f1ed9c3db04902d28f21ae8a2605a00781bc87a1fbc9ac918da4a19fe3c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-feea1561.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Bi6b=AxXjC" ascii
        $s1 = "s&Ibq/orf" ascii
        $s2 = "MvntM<<v?\\" ascii
        $s3 = "rcBzWWTE6" ascii
        $s4 = "kSE7x}Xv" ascii
        $s5 = "AnyPopup" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10182656 and 6 of them
}
