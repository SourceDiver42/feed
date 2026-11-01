rule Sightlines_tlsh_6b6a2854_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6b6a2854"
        date = "2026-10-31"
        campaign = "tlsh-6b6a2854"
        family = ""
        hash = "1be17f4c6bd354f1a5654d9dd30b52a11965d4ac42208d173c73cf9aecb3d8c5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6b6a2854.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/System.Data/Release/net10.0-windows/System.Data.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "IsAotCompatible" ascii
        $s4 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 5 of them
}
