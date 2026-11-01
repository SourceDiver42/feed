rule Sightlines_tlsh_096d1a04_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-096d1a04"
        date = "2026-10-31"
        campaign = "tlsh-096d1a04"
        family = ""
        hash = "1e321f049426f4e1a2d27c742d2a7b335f1dd041793b87011a6e0161c0728d88"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-096d1a04.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Net.WebSockets.Client/Release/net10.0/System.Net.WebSockets.Clie" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "&Unable to connect to the remote serverl" ascii
        $s6 = "DefaultClientKeepAliveInterval" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "InlineArrayAsReadOnlySpan" ascii
        $s9 = "DefaultKeepAliveTimeout" ascii
        $s10 = " featurevalue=\"false\">" ascii
        $s11 = "<>y__InlineArray2`1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
