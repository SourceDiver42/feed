rule Sightlines_tlsh_420d266e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-420d266e"
        date = "2026-10-31"
        campaign = "tlsh-420d266e"
        family = ""
        hash = "2119843c19bd2d1dcc3b2768cfb51c40b40fc31be056a31093e1bc83fadcdb6b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-420d266e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/_/src/runtime/artifacts/obj/System.Diagnostics.FileVersionInfo/Release/net10.0-windows/System.Diagn" ascii
        $s1 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s2 = ".NETCoreApp,Version=v10.0" ascii
        $s3 = "ostics.FileVersionInfo.pdb" ascii
        $s4 = "IsAotCompatible" ascii
        $s5 = ".NET 10.0" ascii
        $s6 = "R4FEcUPn" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 7 of them
}
