rule Sightlines_tlsh_1b4d8ca3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1b4d8ca3"
        date = "2026-10-31"
        campaign = "tlsh-1b4d8ca3"
        family = ""
        hash = "650e48eb0c2c8f2e166bfb1af3ce563ba49424bce9c751c51bcf91d41fc67e64"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1b4d8ca3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s1 = "DebuggerDisableUserUnhandledExceptionsAttribute" ascii
        $s2 = "OverloadResolutionPriorityAttribute" ascii
        $s3 = "CompilerLoweringPreserveAttribute" ascii
        $s4 = "FeatureSwitchDefinitionAttribute" ascii
        $s5 = "IAlternateEqualityComparer`2" ascii
        $s6 = "UnsafeAccessorTypeAttribute" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "InvocationListEnumerator`1" ascii
        $s9 = "ParamCollectionAttribute" ascii
        $s10 = "ExtensionMarkerAttribute" ascii
        $s11 = "SwiftIndirectResult" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
