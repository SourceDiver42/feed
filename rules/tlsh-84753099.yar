rule Sightlines_tlsh_84753099_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-84753099"
        date = "2026-10-31"
        campaign = "tlsh-84753099"
        family = ""
        hash = "3952a72e1f18774f16952b46c20e80ed2bc601a06eca01f33fa924c738022a9c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-84753099.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/System.Configuration/Release/net10.0-windows/System.Configuration.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "IsAotCompatible" ascii
        $s4 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 5 of them
}
