rule Sightlines_tlsh_f7102b92_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f7102b92"
        date = "2026-10-31"
        campaign = "tlsh-f7102b92"
        family = ""
        hash = "3dc81dbc9dacd28261632c94410859eda24c2db50cd6c14309cbb2a434b50c57"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f7102b92.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/netstandard/Release/net10.0-windows/netstandard.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "InvocationListEnumerator`1" ascii
        $s4 = "SpanSplitEnumerator`1" ascii
        $s5 = "ValueSplitEnumerator" ascii
        $s6 = "AlternateLookup`1" ascii
        $s7 = "IsAotCompatible" ascii
        $s8 = "ProcessCpuUsage" ascii
        $s9 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}
