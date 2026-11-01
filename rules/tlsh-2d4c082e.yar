rule Sightlines_tlsh_2d4c082e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2d4c082e"
        date = "2026-10-31"
        campaign = "tlsh-2d4c082e"
        family = ""
        hash = "3bb4d100413ff281ea8a70a22216d8d17d4bcb21610be258d948de4ce6b1a8e5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2d4c082e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Threading/Release/net10.0/System.Threading.pdb" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "4The write lock is being released without being held.H" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "\"&*.26:>BFJNRVZ^bfjnrvz" ascii
        $s8 = "InlineArrayAsReadOnlySpan" ascii
        $s9 = "NamedWaitHandleOptions" ascii
        $s10 = "<>y__InlineArray2`1" ascii
        $s11 = "IsAotCompatible" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
