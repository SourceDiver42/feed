rule Sightlines_signer_cert_sha1_33370058_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-33370058"
        date = "2026-10-29"
        campaign = "signer_cert_sha1-33370058"
        family = ""
        hash = "61abba3a40760a6fef82e61c858195b8a103809b19e267cb1543a718811f8276"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-33370058.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "370624235959Z0r1" ascii
        $s1 = "Greater London1" ascii
        $s2 = "410324235959Z0U1" ascii
        $s3 = "380118235959Z0W1" ascii
        $s4 = "Ly<j}bx^H" ascii
        $s5 = "260325000000Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 32943600 and 6 of them
}
