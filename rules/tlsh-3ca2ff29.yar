rule Sightlines_tlsh_3ca2ff29_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3ca2ff29"
        date = "2026-10-31"
        campaign = "tlsh-3ca2ff29"
        family = ""
        hash = "a87455a818254627457395e85ab4970cc844edf07254456da624a37c99e9a23f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3ca2ff29.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.IO.FileSystem.AccessControl/Release/net10.0-windows/System.IO.Fi" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "#Access to the path '{0}' is denied.~" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "leSystem.AccessControl.pdb" ascii
        $s8 = "eKeys\" featurevalue=\"false\">" ascii
        $s9 = "InlineArrayAsReadOnlySpan" ascii
        $s10 = "<>y__InlineArray2`1" ascii
        $s11 = "<>y__InlineArray3`1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
