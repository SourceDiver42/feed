rule Sightlines_signer_cert_sha1_ad71d7ab_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-ad71d7ab"
        date = "2026-10-28"
        campaign = "signer_cert_sha1-ad71d7ab"
        family = ""
        hash = "07c318c02be5a3a9f1475f5a2d0cd438f4d4ea3288c28e2e10bc5ebbbec8de86"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-ad71d7ab.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Private Organization1" ascii
        $s1 = "The QT Company Oy0" ascii
        $s2 = "The QT Company Oy1" ascii
        $s3 = "371104235959Z0c1" ascii
        $s4 = "380114235959Z0i1" ascii
        $s5 = "281124235959Z0" ascii
        $s6 = "251125000000Z" ascii
        $s7 = "260805000000Z" ascii
        $s8 = "250507000000Z" ascii
        $s9 = "Uusimaa1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 20945520 and 8 of them
}
