rule Sightlines_tlsh_a994399f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a994399f"
        date = "2026-10-31"
        campaign = "tlsh-a994399f"
        family = ""
        hash = "3b85daf02a3d9ed99b84bb1c639fe8b1ced46d8d157fa56f525f6b8c5be43b3e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a994399f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Console/Release/net10.0-windows/System.Console.pdb" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "#Access to the path '{0}' is denied.B" ascii
        $s6 = "HandleSetConsoleEncodingError" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "InlineArrayAsReadOnlySpan" ascii
        $s9 = "ParamCollectionAttribute" ascii
        $s10 = "<>y__InlineArray2`1" ascii
        $s11 = "<>y__InlineArray3`1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
