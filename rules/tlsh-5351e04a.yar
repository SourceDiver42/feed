rule Sightlines_tlsh_5351e04a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5351e04a"
        date = "2026-10-31"
        campaign = "tlsh-5351e04a"
        family = ""
        hash = "44b6003f41da1812c26234d76ee229156310811b45aa658698fb3299936367e4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5351e04a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "ISystem.Net.Http.Json.JsonContent+<SerializeToStreamAsyncTranscoding>d__14" ascii
        $s2 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s3 = "RSystem.Net.Http.Json.HttpClientJsonExtensions+<GetLengthLimitReadStreamAsync>d__15" ascii
        $s4 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s5 = "OSystem.Net.Http.Json.HttpContentJsonExtensions+<GetTranscodingStreamAsync>d__18" ascii
        $s6 = "ZThe request was canceled due to the configured HttpClient.Timeout of {0} seconds elapsing.T" ascii
        $s7 = "/_/src/runtime/artifacts/obj/System.Net.Http.Json/Release/net10.0/System.Net.Http.Json.pdb" ascii
        $s8 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s9 = "<GetFromJsonAsync>b__31_0" ascii
        $s10 = ".NETCoreApp,Version=v10.0" ascii
        $s11 = "InlineArrayAsReadOnlySpan" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
