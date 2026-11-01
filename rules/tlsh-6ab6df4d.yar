rule Sightlines_tlsh_6ab6df4d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6ab6df4d"
        date = "2026-10-31"
        campaign = "tlsh-6ab6df4d"
        family = ""
        hash = "277a84ba155fe7808a514f32694a8157ec9f0eeeef00ef9643e5250004054ff0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6ab6df4d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/System.Xml/Release/net10.0-windows/System.Xml.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "IsAotCompatible" ascii
        $s4 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 5 of them
}
