rule Sightlines_tlsh_c96b6873_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c96b6873"
        date = "2026-10-31"
        campaign = "tlsh-c96b6873"
        family = ""
        hash = "1bf165cee916a854e1150f489e4348ce94755359d5fcdcc0bc2bbbe6a7102bdd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c96b6873.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Diagnostics.TextWriterTraceListener/Release/net10.0/System.Diagn" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "mResourceKeys\" featurevalue=\"false\">" ascii
        $s6 = "ostics.TextWriterTraceListener.pdb" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "IsAotCompatible" ascii
        $s9 = "tE*E4EFELETg" ascii
        $s10 = "f*^5jA:H:P" ascii
        $s11 = ".NET 10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
