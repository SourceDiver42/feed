rule Sightlines_tlsh_438408ae_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-438408ae"
        date = "2026-10-31"
        campaign = "tlsh-438408ae"
        family = ""
        hash = "2cedef51b0a2c2b84240583339ecf2422c650e3388aa46f3494160b93b673887"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-438408ae.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<JavaScriptStringEncode>g__EncodeCore|12_0" ascii
        $s1 = "/_/src/runtime/artifacts/obj/System.Web.HttpUtility/Release/net10.0/System.Web.HttpUtility.pdb" ascii
        $s2 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s3 = "7099398B830009F1C2137ABF489882243CAF03619F29CF2E4EFB264A4101E1F8" ascii
        $s4 = ".NETCoreApp,Version=v10.0" ascii
        $s5 = "s_invalidJavaScriptChars" ascii
        $s6 = "IsAotCompatible" ascii
        $s7 = "s_urlSafeBytes" ascii
        $s8 = "NeedsEncoding" ascii
        $s9 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}
