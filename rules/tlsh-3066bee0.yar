rule Sightlines_tlsh_3066bee0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3066bee0"
        date = "2026-10-31"
        campaign = "tlsh-3066bee0"
        family = ""
        hash = "18a148b3656f45f9d537f7e25a558ba48abbfe103533717344cdf1888d903e6b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3066bee0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Resources.Writer/Release/net10.0/System.Resources.Writer.pdb" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = " Stream does not support seeking.]" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "IsAotCompatible" ascii
        $s8 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 9 of them
}
