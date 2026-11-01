rule Sightlines_tlsh_fa342abe_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fa342abe"
        date = "2026-10-31"
        campaign = "tlsh-fa342abe"
        family = ""
        hash = "10dae312a6697718f8ce3dfcdb17d6ae4b74687c765d74d50de8a8e69e08f5e7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fa342abe.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "0/7686@?LKXW^]_]`]dcedfcgfhcicjckclcmcnconpnqcrcsctcvuwuyxzx" wide
        $s1 = "<RegexGenerator_g>FAD5189FC365C646BC85F408728B63C8346E4C70E77F1DA0C508136C49906F750__ParameterReplac" ascii
        $s2 = "<RegexGenerator_g>FAD5189FC365C646BC85F408728B63C8346E4C70E77F1DA0C508136C49906F750__Utilities" ascii
        $s3 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s4 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s5 = "s_indexOfString_AC244FE541E52CFD90CCD7AB13997D32F9D5031F007841348B9EE5A65488D64E" ascii
        $s6 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s7 = "<GetStandardValues>g__GetTypeDescriptorReflectionType|15_0" ascii
        $s8 = "System.ComponentModel.BrowsableAttribute, System.ComponentModel.Primitives, Version=10.0.0.0, Cultur" ascii
        $s9 = "System.ComponentModel.ReadOnlyAttribute, System.ComponentModel.Primitives, Version=10.0.0.0, Culture" ascii
        $s10 = "System.Diagnostics.CodeAnalysis.RequiresUnreferencedCodeAttribute, System.Runtime, Version=10.0.0.0," ascii
        $s11 = "Justificationk_componentClass is already a protected through [DynamicallyAccessedModifiers(All)] or " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1536624 and 12 of them
}
