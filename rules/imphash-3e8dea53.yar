rule Sightlines_imphash_3e8dea53_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-3e8dea53"
        date = "2026-10-21"
        campaign = "imphash-3e8dea53"
        family = ""
        hash = "1da99d6219c5bc281030ba9d2d5979a6670d9207c8eb76db9815b26ae5dd1ff1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-3e8dea53.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WinHttpSetSecureLegacyServersAppCompat" ascii
        $s1 = "WinHttpGetDefaultProxyConfiguration" ascii
        $s2 = "WinHttpSetDefaultProxyConfiguration" ascii
        $s3 = "WinHttpConnectionUpdateIfIndexTable" ascii
        $s4 = "WinHttpConnectionDeletePolicyEntries" ascii
        $s5 = "WinHttpWebSocketQueryCloseStatus" ascii
        $s6 = "WinHttpWebSocketCompleteUpgrade" ascii
        $s7 = "WinHttpConnectionSetPolicyEntries" ascii
        $s8 = "WinHttpConnectionDeleteProxyInfo" ascii
        $s9 = "WinHttpGetProxySettingsVersion" ascii
        $s10 = "WinHttpConnectionFreeProxyList" ascii
        $s11 = "WinHttpConnectionFreeProxyInfo" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
