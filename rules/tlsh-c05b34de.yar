rule Sightlines_tlsh_c05b34de_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c05b34de"
        date = "2026-10-31"
        campaign = "tlsh-c05b34de"
        family = ""
        hash = "2179bb19f335b4fcacd0994ad2ccfdac6840deff09c7889debfe9dbb5b88a3e6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c05b34de.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.ObjectModel/Release/net10.0/System.ObjectModel.pdb" ascii
        $s4 = "ISystem.Collections.ObjectModel.KeyedCollection`2+KeyedCollectionDebugView" ascii
        $s5 = "+Constructor supports only the '{0}' action.N" ascii
        $s6 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s7 = "KeyedCollectionDebugViewItem" ascii
        $s8 = ".NETCoreApp,Version=v10.0" ascii
        $s9 = "InlineArrayAsReadOnlySpan" ascii
        $s10 = "<>y__InlineArray2`1" ascii
        $s11 = "get_HasSingleTarget" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
