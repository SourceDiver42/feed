rule Sightlines_tlsh_d1571ccf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d1571ccf"
        date = "2026-10-31"
        campaign = "tlsh-d1571ccf"
        family = ""
        hash = "62064d17a313640f4dfb7b7f8116ccbb70b0b9f5b9643a821c99b6a544b8d8a3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d1571ccf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/Microsoft.Win32.Registry/Release/net10.0-windows/Microsoft.Win32.Regist" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "!Cannot write to the registry key.`" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "InlineArrayAsReadOnlySpan" ascii
        $s8 = "<>y__InlineArray2`1" ascii
        $s9 = "IsAotCompatible" ascii
        $s10 = "l(f8VRb_VhPhZmL" ascii
        $s11 = "0,B@HLRQ4qHt6" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
