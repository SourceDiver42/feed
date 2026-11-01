rule Sightlines_signer_cert_sha1_8f60bad4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-8f60bad4"
        date = "2026-10-16"
        campaign = "signer_cert_sha1-8f60bad4"
        family = ""
        hash = "23f04ba936568e9a7c9dce7a6beb52c9be7eb13b734cd390c99e7546cbe1973d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-8f60bad4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "AddTrust External TTP Network1\"0 " ascii
        $s1 = ".?AV_Iostream_error_category@std@@" ascii
        $s2 = "AddTrust External CA Root0" ascii
        $s3 = "Melnikova st. 15, 5 apt.1" ascii
        $s4 = "mail.to.twaego@gmail.com0" ascii
        $s5 = "UTN-USERFirst-Object0" ascii
        $s6 = "Artem Shevchenko0" ascii
        $s7 = "Artem Shevchenko1" ascii
        $s8 = "AddTrust AB1&0$" ascii
        $s9 = "Salt Lake City1" ascii
        $s10 = "301231235959Z0|1" ascii
        $s11 = "200530104838Z0z1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 30458592 and 11 of them
}
