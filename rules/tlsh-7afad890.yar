rule Sightlines_tlsh_7afad890_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7afad890"
        date = "2026-10-28"
        campaign = "tlsh-7afad890"
        family = "mirai"
        hash = "2dcc3fbd2cfb5a1141c3de2879129a9e0bc1ed8e004bee91db28815e5c6ccf10"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7afad890.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s2 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s3 = "HOST: 255.255.255.255:1900" ascii
        $s4 = "MAN: \"ssdp:discover\"" ascii
        $s5 = "M-SEARCH * HTTP/1.1" ascii
        $s6 = "service:service-agent" ascii
        $s7 = "objectClass0" ascii
        $s8 = "TeamSpeak" ascii
        $s9 = " default" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 10 of them
}
