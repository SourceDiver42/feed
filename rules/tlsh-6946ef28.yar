rule Sightlines_tlsh_6946ef28_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6946ef28"
        date = "2026-10-31"
        campaign = "tlsh-6946ef28"
        family = ""
        hash = "00ac175b2b07fe9a7fa1d4247182f0dcbffdb94927a8329bffd45339f1bf0bb6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6946ef28.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Net.NetworkInformation/Release/net10.0-windows/System.Net.Networ" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "<{0} can only be called once for each asynchronous operation.o" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "InlineArrayAsReadOnlySpan" ascii
        $s8 = "\" featurevalue=\"false\">" ascii
        $s9 = "<>y__InlineArray2`1" ascii
        $s10 = "kInformation.pdb" ascii
        $s11 = "IsAotCompatible" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
