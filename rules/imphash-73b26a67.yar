rule Sightlines_imphash_73b26a67_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-73b26a67"
        date = "2026-10-29"
        campaign = "imphash-73b26a67"
        family = ""
        hash = "06c3f201b815a5798816e8c15b925b28f3c38e5aba31efedec10af9e598ce723"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-73b26a67.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "System\\CurrentControlSet\\Services\\EventLog\\System\\WinDivert" ascii
        $s1 = "Filter expression array index is out-of-bounds" ascii
        $s2 = "Filter expression contains a bad token for layer" ascii
        $s3 = "WinDivertHelperFormatIPv4Address" ascii
        $s4 = "WinDivertHelperFormatIPv6Address" ascii
        $s5 = "WinDivertHelperNtohIPv6Address" ascii
        $s6 = "WinDivertHelperNtohIpv6Address" ascii
        $s7 = "Filter object buffer is too short" ascii
        $s8 = "WinDivertHelperParseIPv4Address" ascii
        $s9 = "WinDivertHelperParseIPv6Address" ascii
        $s10 = "WinDivertHelperHtonIPv6Address" ascii
        $s11 = "WinDivertHelperHtonIpv6Address" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
