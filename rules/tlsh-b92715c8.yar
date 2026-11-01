rule Sightlines_tlsh_b92715c8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b92715c8"
        date = "2026-10-31"
        campaign = "tlsh-b92715c8"
        family = ""
        hash = "78915dd1ca144ba8d28ed5c4bfbf35f2796c03d414f6d632481f332b287af85e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b92715c8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/mscorlib/Release/net10.0-windows/mscorlib.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "InvocationListEnumerator`1" ascii
        $s4 = "SpanSplitEnumerator`1" ascii
        $s5 = "AlternateLookup`1" ascii
        $s6 = "IsAotCompatible" ascii
        $s7 = "ProcessCpuUsage" ascii
        $s8 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 9 of them
}
