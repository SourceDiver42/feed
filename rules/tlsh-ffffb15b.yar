rule Sightlines_tlsh_ffffb15b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ffffb15b"
        date = "2026-10-31"
        campaign = "tlsh-ffffb15b"
        family = ""
        hash = "1f4d13e03ecdaf1c1d4f0c8b14c13dde2e9bc06b9945a06d6d2207bfa3ef2958"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ffffb15b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Collections.NonGeneric/Release/net10.0/System.Collections.NonGen" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "<DefaultInvariant>k__BackingField" ascii
        $s6 = "ToDebugViewDictionaryItemArray" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "DebugViewDictionaryItem`2" ascii
        $s9 = "InlineArrayAsReadOnlySpan" ascii
        $s10 = "\" featurevalue=\"false\">" ascii
        $s11 = "<>y__InlineArray3`1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
