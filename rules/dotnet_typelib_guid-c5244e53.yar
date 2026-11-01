rule Sightlines_dotnet_typelib_guid_c5244e53_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-c5244e53"
        date = "2026-10-29"
        campaign = "dotnet_typelib_guid-c5244e53"
        family = "formbook"
        hash = "21af7d776011760bce54d51cefe0416d26888701696ddff544a5f6a307980f43"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-c5244e53.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "(RescueBase.MainForm+<ReadPixelBytes>d__3" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "Helicopter Status: GROUNDED due to weather on ridges." wide
        $s5 = "Operational Summary & Post-Incident Review" wide
        $s6 = "Warning: Team count or fitness below threshold!" wide
        $s7 = "System.Collections.Generic.IEnumerator<System.Byte>.get_Current" ascii
        $s8 = "System.Collections.Generic.IEnumerable<System.Byte>.GetEnumerator" ascii
        $s9 = "Weather alert: Helicopter grounded. Ground carry-off mandatory." wide
        $s10 = "Evacuation successfully completed! Casualty transferred to medical unit." wide
        $s11 = "Mountain Rescue Base Command - .NET 4.5" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1580032 and 12 of them
}
