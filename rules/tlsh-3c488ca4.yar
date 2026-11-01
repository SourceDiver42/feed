rule Sightlines_tlsh_3c488ca4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3c488ca4"
        date = "2026-10-31"
        campaign = "tlsh-3c488ca4"
        family = ""
        hash = "06bb307343db955a312634d00ba5e097cf5168a901284437592c28d780804e33"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3c488ca4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Net.Ping/Release/net10.0-windows/System.Net.Ping.pdb" ascii
        $s4 = "-The system's ping utility could not be found.E" ascii
        $s5 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "IsAotCompatible" ascii
        $s8 = ".NET 10.0" ascii
        $s9 = "%V-j?BFz" ascii
        $s10 = "N*J$~gFz" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 11 of them
}
