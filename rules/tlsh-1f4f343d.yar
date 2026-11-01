rule Sightlines_tlsh_1f4f343d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1f4f343d"
        date = "2026-10-31"
        campaign = "tlsh-1f4f343d"
        family = ""
        hash = "486860152a651e5b8467477821e3534ebc5b2e3ea9d716c1d187e2ca914b1fcc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1f4f343d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Private.Uri/Release/net10.0/System.Private.Uri.pdb" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "<StripBidiControlCharacters>b__27_0" ascii
        $s6 = "LastErrorOkayForRelativeUris" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "InlineArrayAsReadOnlySpan" ascii
        $s9 = "s_asciiOtherThanPercent" ascii
        $s10 = "canonicalizeAsFilePath" ascii
        $s11 = "TryUnescapeDataString" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
