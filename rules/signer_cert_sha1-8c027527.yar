rule Sightlines_signer_cert_sha1_8c027527_netsupport
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-8c027527"
        date = "2026-10-30"
        campaign = "signer_cert_sha1-8c027527"
        family = "netsupport"
        hash = "028c2b444ec7abddb13448c13317d1e26d7a644c65e2371d9115e1b9eff96daa"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-8c027527.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "120614235959Z0\\1" ascii
        $s1 = "131203235959Z0S1" ascii
        $s2 = "TSA2048-1-530" ascii
        $s3 = "Western Cape1" ascii
        $s4 = "Durbanville1" ascii
        $s5 = "image/gif0!0" ascii
        $s6 = "031204000000Z" ascii
        $s7 = "070615000000Z" ascii
        $s8 = "6^bMRQ4q" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 8 of them
}
