rule Sightlines_tlsh_9cc0e7e8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9cc0e7e8"
        date = "2026-10-31"
        campaign = "tlsh-9cc0e7e8"
        family = ""
        hash = "33e99c94cacbff85cdfaa808b0bc4b333eb7067bf9a9a1d49b79e9ebe5e21008"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9cc0e7e8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ">System.Threading.Tasks.Parallel+<>c__49`1+<<ForAsync>b__49_0>d" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s2 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s3 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s4 = "System.Diagnostics.Tracing.EventOpcode, System.Diagnostics.Tracing, Version=10.0.0.0, Culture=neutra" ascii
        $s5 = "/_/src/runtime/artifacts/obj/System.Threading.Tasks.Parallel/Release/net10.0/System.Threading.Tasks." ascii
        $s6 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s7 = "One of the actions was null.u" ascii
        $s8 = ".NETCoreApp,Version=v10.0" ascii
        $s9 = "ys\" featurevalue=\"false\">" ascii
        $s10 = "ForAsyncState`1" ascii
        $s11 = "IsAotCompatible" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
