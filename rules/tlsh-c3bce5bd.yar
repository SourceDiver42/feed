rule Sightlines_tlsh_c3bce5bd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c3bce5bd"
        date = "2026-10-31"
        campaign = "tlsh-c3bce5bd"
        family = ""
        hash = "61807fddfe725fad18e1197fb8fe6580d8cba5ba92317cd07bf5e0ac99a98f62"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c3bce5bd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Threading.Tasks.Dataflow/Release/net10.0/System.Threading.Tasks." ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "at does not utilize this member.u" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "ys\" featurevalue=\"false\">" ascii
        $s8 = "eTEe\\FU\\De\\F5\\G5US5U" ascii
        $s9 = "IsAotCompatible" ascii
        $s10 = "0V<6D*GVZJh\"o" ascii
        $s11 = ";bBFJvVzh*r*{" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
