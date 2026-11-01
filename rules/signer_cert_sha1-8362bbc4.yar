rule Sightlines_signer_cert_sha1_8362bbc4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-8362bbc4"
        date = "2026-10-29"
        campaign = "signer_cert_sha1-8362bbc4"
        family = ""
        hash = "53ab28ec00be6e6f8aefa9ee76fc2735e94d7f3f9dbc06eb2b7ac8cd3084a6af"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-8362bbc4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "chttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Third%20Party%20Component%20CA%202014.crl" ascii
        $s1 = "ehttp://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Third%20Party%20Component%20CA%202014.c" ascii
        $s2 = "/Microsoft Windows Third Party Component CA 20140" ascii
        $s3 = "2Microsoft Windows Hardware Compatibility Publisher0" ascii
        $s4 = "(https://www.microsoft.com/en-us/windows 0" ascii
        $s5 = "FwpsAllocateNetBufferAndNetBufferList0" ascii
        $s6 = "eement which limit liability and are incorporated herein by reference" wide
        $s7 = " Microsoft Code Verification Root0" ascii
        $s8 = "FwpsQueryPacketInjectionState0" ascii
        $s9 = "FwpsInjectNetworkReceiveAsync0" ascii
        $s10 = "KeAcquireInStackQueuedSpinLock" ascii
        $s11 = "KeReleaseInStackQueuedSpinLock" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
