rule Sightlines_tlsh_0b3ac954_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0b3ac954"
        date = "2026-10-31"
        campaign = "tlsh-0b3ac954"
        family = ""
        hash = "3e3a25ea07d35d4bad2d5ac5f3ebeaa3c157ecd479e811b8fb602a2213469122"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0b3ac954.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "System.Diagnostics.Tracing.EventKeywords, System.Diagnostics.Tracing, Version=10.0.0.0, Culture=neut" ascii
        $s4 = "<FormatIPv6Address>g__AppendSections|7_0" ascii
        $s5 = "<ConvertInterfaceNameToLuid>g____PInvoke|17_0" ascii
        $s6 = "<ConvertInterfaceLuidToIndex>g____PInvoke|16_0" ascii
        $s7 = "/_/src/runtime/artifacts/obj/System.Net.Primitives/Release/net10.0-windows/System.Net.Primitives.pdb" ascii
        $s8 = "KeyExchangeAlgorithm, KeyExchangeStrength, CipherAlgorithm, CipherStrength, HashAlgorithm and HashSt" ascii
        $s9 = "System.IUtf8SpanParsable<System.Net.IPNetwork>.TryParse" ascii
        $s10 = "System.IUtf8SpanParsable<System.Net.IPNetwork>.Parse" ascii
        $s11 = "System.IUtf8SpanParsable<System.Net.IPAddress>.TryParse" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
