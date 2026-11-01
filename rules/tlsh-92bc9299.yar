rule Sightlines_tlsh_92bc9299_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-92bc9299"
        date = "2026-10-31"
        campaign = "tlsh-92bc9299"
        family = ""
        hash = "6a7f1310e9ad73aba895e7bebac3fb9b947acbeef10c4372f56b146be9525e39"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-92bc9299.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "System.Diagnostics.Tracing.EventOpcode, System.Diagnostics.Tracing, Version=10.0.0.0, Culture=neutra" ascii
        $s4 = "/_/src/runtime/artifacts/obj/System.Linq.Parallel/Release/net10.0/System.Linq.Parallel.pdb" ascii
        $s5 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s6 = "2Partitioner returned a wrong number of partitions.T" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "IsAotCompatible" ascii
        $s9 = "2.72CBNbazr\"z:" ascii
        $s10 = "C*-EJ%,O=GOIGa" ascii
        $s11 = "Xn3*=NH.M6U*Xn" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1552912 and 12 of them
}
