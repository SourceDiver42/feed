rule Sightlines_tlsh_8dcae7ac_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8dcae7ac"
        date = "2026-11-01"
        campaign = "tlsh-8dcae7ac"
        family = "mirai"
        hash = "4f4abfe2db64294c67144a47ccd28ba63e37602e48d9a241978612d4ffa1d9b9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8dcae7ac.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s2 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s3 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s4 = "SNQUERY: 127.0.0.1:AAAAAA:xsvr" ascii
        $s5 = "HOST: 255.255.255.255:1900" ascii
        $s6 = "MAN: \"ssdp:discover\"" ascii
        $s7 = "M-SEARCH * HTTP/1.1" ascii
        $s8 = "service:service-agent" ascii
        $s9 = "/proc/%d/maps" ascii
        $s10 = "objectClass0" ascii
        $s11 = "/proc/%d/exe" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 10 of them
}
