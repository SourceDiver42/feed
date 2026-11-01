rule Sightlines_tlsh_26ec6c05_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-26ec6c05"
        date = "2026-10-31"
        campaign = "tlsh-26ec6c05"
        family = ""
        hash = "66d618b5522b3e4f7a3c7f2bd872fc378fa6f9bbdca3636854eb1a8cb948e631"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-26ec6c05.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Threading.AccessControl/Release/net10.0-windows/System.Threading" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "ObjectIncompatibleWithCurrentUserOnly" ascii
        $s6 = "<CreateSemaphoreEx>g____PInvoke|35_0" ascii
        $s7 = "<CreateMutexEx>g____PInvoke|31_0" ascii
        $s8 = "<OpenSemaphore>g____PInvoke|34_0" ascii
        $s9 = "<OpenMutex>g____PInvoke|30_0" ascii
        $s10 = ".NETCoreApp,Version=v10.0" ascii
        $s11 = "InlineArrayAsReadOnlySpan" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
