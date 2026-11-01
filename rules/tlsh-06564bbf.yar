rule Sightlines_tlsh_06564bbf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-06564bbf"
        date = "2026-10-31"
        campaign = "tlsh-06564bbf"
        family = ""
        hash = "05e237db20290fbec9e9b51fada3984bed028c659b6c6f1d20385afbe5e88e25"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-06564bbf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Net.WebHeaderCollection/Release/net10.0/System.Net.WebHeaderColl" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "WThis collection holds request headers and cannot contain the specified response header.r" ascii
        $s6 = "<HeaderInfo>k__BackingField" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "InlineArrayAsReadOnlySpan" ascii
        $s9 = "s\" featurevalue=\"false\">" ascii
        $s10 = "<>y__InlineArray2`1" ascii
        $s11 = "IsAotCompatible" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
