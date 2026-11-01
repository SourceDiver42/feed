rule Sightlines_imphash_de2a173e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-de2a173e"
        date = "2026-10-30"
        campaign = "imphash-de2a173e"
        family = ""
        hash = "4f38201f1155aad499ec9101c1da0f4c950e6dc2936cd0d811487fd9e9d4694a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-de2a173e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-8" ascii
        $s1 = "3d0f6d0da78}\"/><supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{35138b9a-" ascii
        $s2 = "soft.NSIS.exehead\" type=\"win32\"/><description>Nullsoft Install System v3.09-4</description><dependen" ascii
        $s3 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s4 = "sembly></dependency><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileg" ascii
        $s5 = "5d96-4fbd-8e2d-a2440225f93a}\"/></application></compatibility></assembly>" ascii
        $s6 = "m.v1\" manifestVersion=\"1.0\"><assemblyIdentity version=\"1.0.0.0\" processorArchitecture=\"*\" name=\"Null" ascii
        $s7 = "cy><dependentAssembly><assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" versio" ascii
        $s8 = "ecurity></trustInfo><compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><" ascii
        $s9 = "es><requestedExecutionLevel level=\"requireAdministrator\" uiAccess=\"false\"/></requestedPrivileges></s" ascii
        $s10 = "\\Microsoft\\Internet Explorer\\Quick Launch" wide
        $s11 = "Installer integrity check has failed. Common causes include" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 8936750 and 12 of them
}
