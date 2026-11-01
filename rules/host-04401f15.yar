rule Sightlines_host_04401f15_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-04401f15"
        date = "2026-10-26"
        campaign = "host-04401f15"
        family = "mirai"
        hash = "1cce1c2c539ed3520b9daad17822996e9c9199bed23b01a8319646ae0033895e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-04401f15.json"
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
        $s9 = "FICMUHDKPJKCF" ascii
        $s10 = "objectClass0" ascii
        $s11 = "NKLWZQJGNN\"" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}
