rule Sightlines_tlsh_70c8eede_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-70c8eede"
        date = "2026-10-31"
        campaign = "tlsh-70c8eede"
        family = ""
        hash = "14ed0e4a1832a085eb655a6725f2dc841b53a08396979609f0814578896857d7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-70c8eede.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/System.Xml.ReaderWriter/Release/net10.0/System.Xml.ReaderWriter.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "IsAotCompatible" ascii
        $s4 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 5 of them
}
