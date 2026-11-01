rule Sightlines_tlsh_f4deb7f8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f4deb7f8"
        date = "2026-10-31"
        campaign = "tlsh-f4deb7f8"
        family = ""
        hash = "226e216e33c94ef7594bdffe670ba4dc5907151c113cb41ac9e9d570227e1765"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f4deb7f8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Text.Encoding.CodePages/Release/net10.0-windows/System.Text.Enco" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "9349424C68362DE2254D1700998A977AD514CF7ADAE27F13064ABF0EF862B87F2" ascii
        $s6 = "<InternalSyncObject>k__BackingField" ascii
        $s7 = "ABD322411B1F0549AAFB728BDC99B5ACD22BDD1AE854CDAA38C71BFB922BBDF1" ascii
        $s8 = ".NETCoreApp,Version=v10.0" ascii
        $s9 = "InlineArrayAsReadOnlySpan" ascii
        $s10 = "get_MappedFamilyCodePage" ascii
        $s11 = "s\" featurevalue=\"false\">" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1724944 and 12 of them
}
