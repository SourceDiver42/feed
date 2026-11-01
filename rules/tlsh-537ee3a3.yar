rule Sightlines_tlsh_537ee3a3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-537ee3a3"
        date = "2026-10-31"
        campaign = "tlsh-537ee3a3"
        family = ""
        hash = "34b3475af3a7b4c16a9215f15e8abb39d8474fb77f9355c029c3599e3ab0e471"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-537ee3a3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Memory/Release/net10.0/System.Memory.pdb" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "6Release all references before disposing this instance.?" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "InlineArrayAsReadOnlySpan" ascii
        $s8 = " $(,048<@DHLPTX\\`dhl" ascii
        $s9 = "SpanSplitEnumerator`1" ascii
        $s10 = "<>y__InlineArray2`1" ascii
        $s11 = "\"&*.26:>BFJNRVZ" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
