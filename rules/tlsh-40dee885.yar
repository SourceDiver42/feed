rule Sightlines_tlsh_40dee885_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-40dee885"
        date = "2026-10-31"
        campaign = "tlsh-40dee885"
        family = ""
        hash = "1bb8def6afbc0e53098c4d2583be77e6684e85cccafd8b397783db89767dc834"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-40dee885.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "}BinaryFormatter serialization and deserialization have been removed. See https://aka.ms/binaryforma" ascii
        $s4 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s5 = "sourceKeys\" featurevalue=\"false\">" ascii
        $s6 = "Serialization.Formatters.pdb" ascii
        $s7 = ".NETCoreApp,Version=v10.0" ascii
        $s8 = "get_BinaryFormatter_Removed" ascii
        $s9 = "InlineArrayAsReadOnlySpan" ascii
        $s10 = "tter for more information." ascii
        $s11 = "<>y__InlineArray2`1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
