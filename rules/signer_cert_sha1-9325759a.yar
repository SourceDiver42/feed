rule Sightlines_signer_cert_sha1_9325759a_netsupport
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-9325759a"
        date = "2026-10-15"
        campaign = "signer_cert_sha1-9325759a"
        family = "netsupport"
        hash = "06a0a243811e9c4738a9d413597659ca8d07b00f640b74adc9cb351c179b3268"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-9325759a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".Netsupport House Towngate East, Market Deeping1" ascii
        $s1 = "!Copyright (c) 2023 NetSupport Ltd" wide
        $s2 = "is@netsupportsoftware.com0" ascii
        $s3 = "Private Organization1" ascii
        $s4 = "NETSUPPORT LTD.1(0&" ascii
        $s5 = "Peterborough1705" ascii
        $s6 = "341209171340Z0]1" ascii
        $s7 = "250617130115Z0" ascii
        $s8 = "220617130115Z" ascii
        $s9 = "300728000000Z0\\1" ascii
        $s10 = "231107171340Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}
