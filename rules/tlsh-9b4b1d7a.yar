rule Sightlines_tlsh_9b4b1d7a_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9b4b1d7a"
        date = "2026-11-01"
        campaign = "tlsh-9b4b1d7a"
        family = "mirai"
        hash = "3e8de9edafa71f4399820fb5ea8785041807b9300ab0a9739d0bb49cca03dd01"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9b4b1d7a.json"
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
        $s8 = "/lib/ld-uClibc.so.0" ascii
        $s9 = "__aeabi_uidivmod" ascii
        $s10 = "__errno_location" ascii
        $s11 = "__uClibc_main" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
