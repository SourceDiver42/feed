rule Sightlines_tlsh_fc22535c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fc22535c"
        date = "2026-10-31"
        campaign = "tlsh-fc22535c"
        family = ""
        hash = "2ccdc3fe937585aeb3473000be6fb45dab254f6198676c626846d59f2362ec68"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fc22535c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ">System.Security.Claims.ClaimsIdentity+<<FindAll>g__Core|63_0>d" ascii
        $s1 = ">System.Security.Claims.ClaimsIdentity+<<FindAll>g__Core|64_0>d" ascii
        $s2 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s3 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s4 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s5 = "CSystem.Security.Claims.ClaimsIdentity+<CombinedClaimsIterator>d__42" ascii
        $s6 = "/_/src/runtime/artifacts/obj/System.Security.Claims/Release/net10.0/System.Security.Claims.pdb" ascii
        $s7 = "mThe StringComparison must be one of Ordinal, OrdinalIgnoreCase, InvariantCulture, InvariantCultureI" ascii
        $s8 = "InvalidOperationException_ActorGraphCircularo" wide
        $s9 = "ArgumentException_StringComparisonCultureAware" wide
        $s10 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s11 = "YThis instance contains state that cannot be serialized and deserialized on this platform.Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
