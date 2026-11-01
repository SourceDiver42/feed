rule Sightlines_tlsh_062ff058_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-062ff058"
        date = "2026-10-31"
        campaign = "tlsh-062ff058"
        family = ""
        hash = "6758af6c57fe08ab2ef3426ab4fb7510c5a7c13948aaedf81339a33d8ee54250"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-062ff058.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/System.Core/Release/net10.0-windows/System.Core.pdb" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "AlternateLookup`1" ascii
        $s4 = "IsAotCompatible" ascii
        $s5 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 6 of them
}
