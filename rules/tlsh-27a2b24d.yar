rule Sightlines_tlsh_27a2b24d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-27a2b24d"
        date = "2026-10-31"
        campaign = "tlsh-27a2b24d"
        family = ""
        hash = "d2677e25b164af13d28032b03fd6eb30a4fcc3d9ced4771eaab11cd7d8721216"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-27a2b24d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s4 = "sourceKeys\" featurevalue=\"false\">" ascii
        $s5 = "Serialization.Primitives.pdb" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "IsAotCompatible" ascii
        $s8 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 9 of them
}
