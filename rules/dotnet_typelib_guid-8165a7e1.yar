rule Sightlines_dotnet_typelib_guid_8165a7e1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-8165a7e1"
        date = "2026-10-20"
        campaign = "dotnet_typelib_guid-8165a7e1"
        family = ""
        hash = "9db92c127123dcc94f94e84e8745faa84420f8235069478f7081dce39f4452c3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-8165a7e1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "DILUVIUM! Flumen inundat cavernam (Flood pulse cleans sediment & fills channels)." wide
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "RUINA! Eventus collapsus factus est! (A collapse event occurred!)" wide
        $s5 = "Configuratio servata est! (Configuration saved successfully)" wide
        $s6 = "Raining! Aqua crescit in siphone (Rain level rises in the sump)." wide
        $s7 = "Calcit Saturation must be between 0 and 100!" wide
        $s8 = "C290034A97A61A2F8BE41E55B594BC89F452E69C81BDAAFD00ADEF95BB51419A" ascii
        $s9 = "CD1BA97F43CC8DC3152172D7F2EA7B953ADE66EE8713FFA8E1DEEFC30CCCC45B" ascii
        $s10 = "24C80B0C1D0F8977AA8C6ED3633A88E27663B9FBFFACF2EEE8A488EB3A86FE14" ascii
        $s11 = "CaveSystem.Properties.Resources.resources" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2165760 and 12 of them
}
