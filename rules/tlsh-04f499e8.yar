rule Sightlines_tlsh_04f499e8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-04f499e8"
        date = "2026-10-31"
        campaign = "tlsh-04f499e8"
        family = ""
        hash = "2311a3f92971de918943573dfb66e04e25c1d543663951eb24e8eb1a0dcd4251"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-04f499e8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "<GetWindowsAccountDomainSid>g____PInvoke|19_0" ascii
        $s3 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s4 = "<AllocateLocallyUniqueId>g____PInvoke|28_0" ascii
        $s5 = "/_/src/runtime/artifacts/obj/System.Security.Principal.Windows/Release/net10.0-windows/System.Securi" ascii
        $s6 = "<ImpersonateLoggedOnUser>g____PInvoke|25_0" ascii
        $s7 = "<CheckTokenMembership>g____PInvoke|29_0" ascii
        $s8 = "BWindows Principal functionality is not supported on this platform.{" ascii
        $s9 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s10 = "<CreateWellKnownSid>g____PInvoke|16_0" ascii
        $s11 = "<IsEqualDomainSid>g____PInvoke|21_0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
