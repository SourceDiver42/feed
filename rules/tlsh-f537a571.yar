rule Sightlines_tlsh_f537a571_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f537a571"
        date = "2026-10-31"
        campaign = "tlsh-f537a571"
        family = ""
        hash = "079cf4a6a2c9ec77b9e03f0222740f9eaf9f5e7359a16fbf3450ad7bc44de321"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f537a571.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.ComponentModel.Primitives/Release/net10.0/System.ComponentModel." ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "<WindowStyle>k__BackingField" ascii
        $s6 = "<Appearance>k__BackingField" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "<DragDrop>k__BackingField" ascii
        $s9 = "<Behavior>k__BackingField" ascii
        $s10 = "<Layout>k__BackingField" ascii
        $s11 = "InlineArrayAsReadOnlySpan" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
