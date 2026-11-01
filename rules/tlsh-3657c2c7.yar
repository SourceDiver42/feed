rule Sightlines_tlsh_3657c2c7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3657c2c7"
        date = "2026-10-31"
        campaign = "tlsh-3657c2c7"
        family = ""
        hash = "1b19d86241bb7a033f30946d4556440258d2d88793a26465bccced7d2b44b93c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3657c2c7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Collections.Specialized/Release/net10.0/System.Collections.Speci" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "POnDeserialization method was called while the object was not being deserialized.r" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "InlineArrayAsReadOnlySpan" ascii
        $s8 = " $(,048<@DHLPTX\\`dhl" ascii
        $s9 = "s\" featurevalue=\"false\">" ascii
        $s10 = "<>y__InlineArray2`1" ascii
        $s11 = "IsAotCompatible" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
