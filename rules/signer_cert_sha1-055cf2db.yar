rule Sightlines_signer_cert_sha1_055cf2db_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-055cf2db"
        date = "2026-10-16"
        campaign = "signer_cert_sha1-055cf2db"
        family = ""
        hash = "086e083da4e7a46438aff3188beb2c0d14cb38af216c62a880cd8209dfcfcca8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-055cf2db.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "250911201113Z0t1" ascii
        $s1 = "230012+5029260" ascii
        $s2 = "240912201113Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2816096 and 3 of them
}
