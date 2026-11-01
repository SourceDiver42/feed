rule Sightlines_tlsh_338aa0ef_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-338aa0ef"
        date = "2026-10-31"
        campaign = "tlsh-338aa0ef"
        family = ""
        hash = "0e0c0cbf20342fd2d3e3fdd1e2468382b2e64bfe6496277ff20002d518e5aac9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-338aa0ef.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "System.Text.RegularExpressions.RegexOptions, System.Text.RegularExpressions, Version=10.0.0.0, Cultu" ascii
        $s1 = "/_/src/runtime/artifacts/obj/System.Net.WebProxy/Release/net10.0/System.Net.WebProxy.pdb" ascii
        $s2 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s3 = ".NETCoreApp,Version=v10.0" ascii
        $s4 = "IsAotCompatible" ascii
        $s5 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 6 of them
}
