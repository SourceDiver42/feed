rule Sightlines_tlsh_acbf1669_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-acbf1669"
        date = "2026-10-31"
        campaign = "tlsh-acbf1669"
        family = ""
        hash = "532f8921e2200f2d3ea13549e71ff85e5c2d6f292f44c40ac6e1bec760928b15"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-acbf1669.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "CThe provided proxy type '{0}' must be derived from 'DispatchProxy'.u" ascii
        $s4 = "/_/src/runtime/artifacts/obj/System.Reflection.DispatchProxy/Release/net10.0/System.Reflection.Dispa" ascii
        $s5 = "DDispatchProxy does not support invocation of static virtual members." ascii
        $s6 = "get_DispatchProxy_Method_Invocation_Cannot_Be_Static" ascii
        $s7 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s8 = ".NETCoreApp,Version=v10.0" ascii
        $s9 = "InlineArrayAsReadOnlySpan" ascii
        $s10 = "ys\" featurevalue=\"false\">" ascii
        $s11 = "DispatchProxyTypes." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
