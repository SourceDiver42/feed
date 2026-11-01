rule Sightlines_tlsh_1a7755a7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1a7755a7"
        date = "2026-10-29"
        campaign = "tlsh-1a7755a7"
        family = ""
        hash = "66b458d7ad2ea9db7771f656892bf95a330cf243f4914cd01fbcdbd3b3eaacc3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1a7755a7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "The WinDivert 2.2 driver [URL: https://reqrypt.org/windivert.html] [Bitcoin: 1C5vZVSbizPeZ8ydTYhUfm4" wide
        $s1 = "WinDivert2.2_SubLayerFlowEstablishedIPv4" wide
        $s2 = "WinDivert2.2_SubLayerFlowEstablishedIPv6" wide
        $s3 = "chttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Third%20Party%20Component%20CA%202014.crl" ascii
        $s4 = "ehttp://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Third%20Party%20Component%20CA%202014.c" ascii
        $s5 = "WinDivert2.2_SubLayerEndpointClosureIPv4" wide
        $s6 = "WinDivert2.2_SubLayerEndpointClosureIPv6" wide
        $s7 = "WinDivert2.2 sublayer flow established (IPv4)" wide
        $s8 = "WinDivert2.2 sublayer flow established (IPv6)" wide
        $s9 = "WinDivert2.2_SubLayerOutboundNetworkIPv4" wide
        $s10 = "WinDivert2.2_SubLayerOutboundNetworkIPv6" wide
        $s11 = "WinDivert2.2 callout flow established (IPv6)" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
