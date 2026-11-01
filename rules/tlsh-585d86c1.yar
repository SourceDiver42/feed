rule Sightlines_tlsh_585d86c1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-585d86c1"
        date = "2026-10-31"
        campaign = "tlsh-585d86c1"
        family = ""
        hash = "644956324add90895e75e0f6874beeac35713c62beb0bb5c0abb31d4cde7dc76"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-585d86c1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Diagnostics.TraceSource/Release/net10.0/System.Diagnostics.Trace" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "QAttempted to set {0} to a value that is too low.  Setting level to TraceLevel.Offr" ascii
        $s6 = "<CorrelationManager>k__BackingField" ascii
        $s7 = "OverloadResolutionPriorityAttribute" ascii
        $s8 = "<InitializedLock>k__BackingField" ascii
        $s9 = ".NETCoreApp,Version=v10.0" ascii
        $s10 = "<Callstack>k__BackingField" ascii
        $s11 = "<AppName>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
