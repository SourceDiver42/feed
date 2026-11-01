rule Sightlines_tlsh_5b2d5f51_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5b2d5f51"
        date = "2026-10-31"
        campaign = "tlsh-5b2d5f51"
        family = ""
        hash = "17e157aacc2c749ea27ef5cd6668ba270e5438587013e77d9c87837d9659914a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5b2d5f51.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Linq.Queryable/Release/net10.0/System.Linq.Queryable.pdb" ascii
        $s4 = "wThe Queryable MinBy and MaxBy taking an IComparer<TSource> are obsolete. Use the new ones that take" ascii
        $s5 = "KThere is no method '{0}' on type '{1}' that matches the specified argumentsW" ascii
        $s6 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s7 = "OverloadResolutionPriorityAttribute" ascii
        $s8 = ".NETCoreApp,Version=v10.0" ascii
        $s9 = "InlineArrayAsReadOnlySpan" ascii
        $s10 = " an IComparer<TKey>." ascii
        $s11 = "\"*(F0F8F@BHNP&S*Yfh" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
