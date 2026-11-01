rule Sightlines_dotnet_typelib_guid_a714f431_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-a714f431"
        date = "2026-10-23"
        campaign = "dotnet_typelib_guid-a714f431"
        family = ""
        hash = "1d0f2d9db8cc9498ffed71d038690bfe52b39b3a1771bbfae0088db2d603cca0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-a714f431.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676" wide
        $s1 = "9uzQZ8M9esiGktQ2p1awgW2VefNvdHItyTIJRslztZk=" wide
        $s2 = "BCrypt.BCryptSetAlgorithmProperty(BCrypt.BCRYPT_CHAINING_MODE, BCrypt.BCRYPT_CHAIN_MODE_GCM) failed " wide
        $s3 = "zMaRPCbE0Gb4k/zB6ZNS3r1L34TENqMZD9RW6hkhoOE=" wide
        $s4 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s5 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows Messaging Subsystem\\Profiles\\Outlook\\9375CFF041" wide
        $s6 = "Software\\Microsoft\\Office\\15.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676" wide
        $s7 = "Software\\Microsoft\\Office\\16.0\\Outlook\\Profiles\\Outlook\\9375CFF0413111d3B88A00104B2A6676" wide
        $s8 = "BCrypt.BCryptOpenAlgorithmProvider() failed with status code:{0}" wide
        $s9 = "      <!--<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\" />-->" ascii
        $s10 = "      <!--<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\" />-->" ascii
        $s11 = "      <!--<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\" />-->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
