rule Sightlines_mutex_901029f8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign mutex-901029f8"
        date = "2026-10-23"
        campaign = "mutex-901029f8"
        family = ""
        hash = "17bf039a9a73ecb31518e497cf516bdb7fa2468e156d352712cb928eb3e33fa1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/mutex-901029f8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\">" ascii
        $s1 = "KmuX}}O|zmvk|}\\az|impvwQxw}u|k" ascii
        $s2 = "STEP after HomeCast NULL" ascii
        $s3 = "STEP before Invoke_3" ascii
        $s4 = "STEP after Invoke_3" ascii
        $s5 = "D$XH9D$xsIHcD$0H9D$xs=H" ascii
        $s6 = "STEP after VeilCast" ascii
        $s7 = "STEP before FaceArm" ascii
        $s8 = "CertOpenSystemStoreW" ascii
        $s9 = "fKq]LjUYKsZoY_HUSR" ascii
        $s10 = "STEP after FaceArm" ascii
        $s11 = "Custom Gradient" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 31400960 and 12 of them
}
