rule Sightlines_tlsh_1b772e07_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1b772e07"
        date = "2026-10-31"
        campaign = "tlsh-1b772e07"
        family = ""
        hash = "369c8de4c2de87614987d65834a5ae86d56c5ec3e3659f4626e8925575f932c0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1b772e07.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.IO.Pipes/Release/net10.0-windows/System.IO.Pipes.pdb" ascii
        $s4 = "<TryConnect>g__CreateNamedPipeClient|30_0" ascii
        $s5 = ">Specifying PipeAccessRights is not supported on this platform." ascii
        $s6 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s7 = "KCould not connect to the pipe because it was not owned by the current user.E" ascii
        $s8 = "PlatformNotSupported_PipeAccessRights" wide
        $s9 = ".NETCoreApp,Version=v10.0" ascii
        $s10 = "AccessRightsFromDirection" ascii
        $s11 = "InlineArrayAsReadOnlySpan" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
