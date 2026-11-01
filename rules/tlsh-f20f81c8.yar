rule Sightlines_tlsh_f20f81c8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f20f81c8"
        date = "2026-10-31"
        campaign = "tlsh-f20f81c8"
        family = ""
        hash = "0a7f3dd2fb6147a3fc046aeac8501d764effe5a3d8cfa56d2b244aa50b874b98"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f20f81c8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.IO.FileSystem.DriveInfo/Release/net10.0-windows/System.IO.FileSy" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "#Access to the path '{0}' is denied.r" ascii
        $s6 = ".NETCoreApp,Version=v10.0" ascii
        $s7 = "InlineArrayAsReadOnlySpan" ascii
        $s8 = "s\" featurevalue=\"false\">" ascii
        $s9 = "<>y__InlineArray2`1" ascii
        $s10 = "<>y__InlineArray3`1" ascii
        $s11 = "stem.DriveInfo.pdb" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
