rule Sightlines_tlsh_c4f4be9c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c4f4be9c"
        date = "2026-10-31"
        campaign = "tlsh-c4f4be9c"
        family = ""
        hash = "5ba32bcde2d72362db2d6e02763ece79fa35bc878b50493e956ce594307e997f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c4f4be9c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "System.Security.Permissions.SecurityPermissionAttribute, System.Private.CoreLib, Version=10.0.0.0, C" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "#Failed to marshal Promise callback." ascii
        $s6 = "ResourceKeys\" featurevalue=\"false\">" ascii
        $s7 = "get_FailedToMarshalPromiseHolder" ascii
        $s8 = "e.InteropServices.JavaScript.pdb" ascii
        $s9 = ".NETCoreApp,Version=v10.0" ascii
        $s10 = "InlineArrayAsReadOnlySpan" ascii
        $s11 = "PromiseHolder is null." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
