rule Sightlines_dotnet_typelib_guid_788d52d8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-788d52d8"
        date = "2026-10-22"
        campaign = "dotnet_typelib_guid-788d52d8"
        family = ""
        hash = "13cee49212b02538acec3887804d62cd696f29cbe37e5231809f16f384619be9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-788d52d8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Couldnt set the shellcode memory as PAGE_EXECUTE_READWRITE!" wide
        $s1 = "AntiAnalysis: Suspicious Machine GUID detected! Self-destructing..." wide
        $s2 = "SOFTWARE\\WOW6432Node\\Clients\\StartMenuInternet" wide
        $s3 = "SOFTWARE\\Classes\\Foxmail.url.mailto\\Shell\\open\\command" wide
        $s4 = "\\NETGATE Technologies\\BlackHawk\\Profiles" wide
        $s5 = "AntiAnalysis: Suspicious GPU detected! Self-destructing..." wide
        $s6 = "AntiAnalysis: Suspicious PC name detected! Self-destructing..." wide
        $s7 = "AntiAnalysis: Failed to retrieve Machine GUID. Exception: " wide
        $s8 = "AntiAnalysis: Suspicious PC username detected! Self-destructing..." wide
        $s9 = "HARDWARE\\Description\\System\\CentralProcessor\\0" wide
        $s10 = "AntiAnalysis: Suspicious IP detected! Self-destructing..." wide
        $s11 = "SystemPortableWorkspaceEfiLauncherInformation" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4016128 and 12 of them
}
