rule Sightlines_dotnet_typelib_guid_1d2d4d62_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-1d2d4d62"
        date = "2026-10-28"
        campaign = "dotnet_typelib_guid-1d2d4d62"
        family = "agenttesla"
        hash = "1216a457ad6feba882414c1d842764b2ef56b281cc6d73248732a8b5f96cf37f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-1d2d4d62.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "-NuclearControl.PlantForm+<ReadPixelBytes>d__6" ascii
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "<MashlmutaHandoverQuality>k__BackingField" ascii
        $s4 = "<MshakhnaSupervisorOversight>k__BackingField" ascii
        $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s6 = "System.Collections.Generic.IEnumerator<System.Byte>.get_Current" ascii
        $s7 = "System.Collections.Generic.IEnumerable<System.Byte>.GetEnumerator" ascii
        $s8 = "Operator Shift & Human Factors Configuration" wide
        $s9 = "System.Collections.Generic.IEnumerator<System.Byte>.Current" ascii
        $s10 = "Nuclear Performance & Operations Summary Report" wide
        $s11 = "<DukhranaShiftPosition>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2668544 and 12 of them
}
