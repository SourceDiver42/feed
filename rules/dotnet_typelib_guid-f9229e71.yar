rule Sightlines_dotnet_typelib_guid_f9229e71_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-f9229e71"
        date = "2026-10-24"
        campaign = "dotnet_typelib_guid-f9229e71"
        family = ""
        hash = "2545a93d9e794363f95aafcba44b1e791621e801ac887eecd44ed9b5f2273195"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-f9229e71.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "Calves Surviving: {0} ({1} born this cycle)" wide
        $s3 = "Lichen Pasture Recovery: {0:F1}% average biomass" wide
        $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s5 = "Snow Crust Lockout: Active hard crust (Foraging impaired)" wide
        $s6 = "Snow Depth: {0:F1} cm (Albedo {1:F0}%)" wide
        $s7 = "Predation Losses: {0} kills | Crust starvation: {1}" wide
        $s8 = "Supplementary Feed Stations: {0} active depots" wide
        $s9 = "Calving Success: {0} calves born to date" wide
        $s10 = "Predation Losses: {0} | Crust Starvation: {1}" wide
        $s11 = "Summer Insect Harassment: {0:F0}% intensity" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2316288 and 12 of them
}
