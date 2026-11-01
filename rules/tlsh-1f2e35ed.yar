rule Sightlines_tlsh_1f2e35ed_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1f2e35ed"
        date = "2026-10-31"
        campaign = "tlsh-1f2e35ed"
        family = ""
        hash = "227ecb036594a171e73c3144f8767bf722bce2a89c6b09693d5931e951e79357"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1f2e35ed.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/System.Security/Release/net10.0-windows/System.Security.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "IsAotCompatible" ascii
        $s4 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 5 of them
}
