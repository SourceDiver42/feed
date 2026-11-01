rule Sightlines_signer_cert_sha1_4eb24eef_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-4eb24eef"
        date = "2026-10-31"
        campaign = "signer_cert_sha1-4eb24eef"
        family = ""
        hash = "145ade963eba427027d5e1381db5d51a0ef9e98e9fef9efbfa6074ca20da246f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-4eb24eef.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "260617182137Z0t1" ascii
        $s1 = "250619182137Z" ascii
        $s2 = "230012+5053590" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3632176 and 3 of them
}
