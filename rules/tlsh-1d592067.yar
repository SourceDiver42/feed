rule Sightlines_tlsh_1d592067_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1d592067"
        date = "2026-10-29"
        campaign = "tlsh-1d592067"
        family = "mirai"
        hash = "1d1246dae68db71d2e6dc97c788460effd5286f477466a1b8851a0628f0acce1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1d592067.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s2 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s3 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s4 = "HOST: 255.255.255.255:1900" ascii
        $s5 = "MAN: \"ssdp:discover\"" ascii
        $s6 = "M-SEARCH * HTTP/1.1" ascii
        $s7 = "service:service-agent" ascii
        $s8 = "objectClass0" ascii
        $s9 = "TeamSpeak" ascii
        $s10 = " default" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}
