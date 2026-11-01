rule Sightlines_tlsh_a8987623_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a8987623"
        date = "2026-10-31"
        campaign = "tlsh-a8987623"
        family = ""
        hash = "52b6d020341114450dc3cfa0d5218f8cf841d40e0f729ffc5d5d0164832b0350"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a8987623.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.ComponentModel.EventBasedAsync/Release/net10.0/System.ComponentM" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "urceKeys\" featurevalue=\"false\">" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "odel.EventBasedAsync.pdb" ascii
        $s8 = "IsAotCompatible" ascii
        $s9 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}
