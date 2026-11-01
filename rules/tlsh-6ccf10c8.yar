rule Sightlines_tlsh_6ccf10c8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6ccf10c8"
        date = "2026-10-31"
        campaign = "tlsh-6ccf10c8"
        family = ""
        hash = "21e9db02782d569548e1ef988b50220ed5912de210681a34130bedda72399e5d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6ccf10c8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "MSystem.Reflection.TypeExtensions is not supported on NET Standard 1.3 or 1.5.x" ascii
        $s4 = "/_/src/runtime/artifacts/obj/System.Reflection.TypeExtensions/Release/net10.0/System.Reflection.Type" ascii
        $s5 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "eys\" featurevalue=\"false\">" ascii
        $s8 = "IsAotCompatible" ascii
        $s9 = "Extensions.pdb" ascii
        $s10 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 11 of them
}
