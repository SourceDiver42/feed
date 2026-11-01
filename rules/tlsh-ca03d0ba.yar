rule Sightlines_tlsh_ca03d0ba_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ca03d0ba"
        date = "2026-10-31"
        campaign = "tlsh-ca03d0ba"
        family = ""
        hash = "577d95471cbfdc0d53e4a732c58b3dd1fdd997eca166bcca68bcb68c08dc1898"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ca03d0ba.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/System/Release/net10.0-windows/System.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "PoolingPointerMemoryManager" ascii
        $s4 = "ValueSplitEnumerator" ascii
        $s5 = "TruncatedReadStream" ascii
        $s6 = "IsAotCompatible" ascii
        $s7 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 8 of them
}
