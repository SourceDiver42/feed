rule Sightlines_tlsh_f6eb7540_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f6eb7540"
        date = "2026-10-31"
        campaign = "tlsh-f6eb7540"
        family = ""
        hash = "1222dcfa31f149796cc0bdc73004e29e3b57dd7eaa11133e5e214eac606bfc9a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f6eb7540.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Net.WebClient/Release/net10.0/System.Net.WebClient.pdb" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "%The message length limit was exceededT" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "IsAotCompatible" ascii
        $s8 = "value=\"false\">" ascii
        $s9 = ",F86@vR:Zj" ascii
        $s10 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 11 of them
}
