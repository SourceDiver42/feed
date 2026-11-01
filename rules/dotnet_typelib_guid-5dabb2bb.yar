rule Sightlines_dotnet_typelib_guid_5dabb2bb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-5dabb2bb"
        date = "2026-10-27"
        campaign = "dotnet_typelib_guid-5dabb2bb"
        family = ""
        hash = "0709bd241f958483f396fe85fefaa5e38fcf0f06c9fbacbe3dc67e130859fab4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-5dabb2bb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s1 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s2 = "$29840822-5B84-11D0-BD3B-00A0C911CE86" ascii
        $s3 = "RtlSetProcessIsCritical" ascii
        $s4 = "NtProtectVirtualMemory" ascii
        $s5 = "CreateClassEnumerator" ascii
        $s6 = "ICreateDevEnum" ascii
        $s7 = "Copyright " ascii
        $s8 = "masterKey" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 8707072 and 9 of them
}
