rule Sightlines_imphash_e3e50016_revstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e3e50016"
        date = "2026-10-31"
        campaign = "imphash-e3e50016"
        family = "revstealer"
        hash = "751798ddfdcfe032cf8a96e56b528f66d5e6619d509e298f74ca9fc29ccafbca"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e3e50016.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ShellAboutW" ascii
        $s1 = "[+NCSPyx" ascii
        $s2 = "xIN>]-fQ" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9473024 and 3 of them
}
