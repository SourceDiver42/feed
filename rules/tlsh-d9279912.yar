rule Sightlines_tlsh_d9279912_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d9279912"
        date = "2026-10-31"
        campaign = "tlsh-d9279912"
        family = ""
        hash = "3dfe11fb30c5f84c911d9562be6c2037113cd8976ef2def3550ac415ae58955b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d9279912.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ")(*(32768796:6<;=;@?A?B?CBD?IHLKONTSUSWVYXhglkmlnlolplqkrqsqtkukvkwkxkykzk{k|k}k" wide
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s2 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s3 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s4 = "System.Diagnostics.Tracing.EventKeywords, System.Diagnostics.Tracing, Version=10.0.0.0, Culture=neut" ascii
        $s5 = "DOnly HTTP/1.0 and HTTP/1.1 version requests are currently supported.]" ascii
        $s6 = "/_/src/runtime/artifacts/obj/System.Net.HttpListener/Release/net10.0-windows/System.Net.HttpListener" ascii
        $s7 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s8 = "<InputStream>k__BackingField" ascii
        $s9 = ".NETCoreApp,Version=v10.0" ascii
        $s10 = "InlineArrayAsReadOnlySpan" ascii
        $s11 = "X509CertificateLoader" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1069680 and 12 of them
}
