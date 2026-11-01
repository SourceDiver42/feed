rule Sightlines_tlsh_7dd42629_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7dd42629"
        date = "2026-10-31"
        campaign = "tlsh-7dd42629"
        family = ""
        hash = "0ad1db4be167f3c0ddc187a2a046f0ed83e70d5cf772550fecbdc82f650a9ee4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7dd42629.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "/_/src/runtime/artifacts/obj/System.Formats.Asn1/Release/net10.0/System.Formats.Asn1.pdb" ascii
        $s4 = "RProvides classes that can read and write the ASN.1 BER, CER, and DER data formats." ascii
        $s5 = "<ParseGeneralizedTime>g__GetNextState|43_0" ascii
        $s6 = "HThe AsnWriter cannot be written to while performing the Encode callback." ascii
        $s7 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s8 = "get_AsnWriter_ModifyingWhileEncoding" ascii
        $s9 = ".NETCoreApp,Version=v10.0" ascii
        $s10 = "InlineArrayAsReadOnlySpan" ascii
        $s11 = "<>y__InlineArray2`1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
