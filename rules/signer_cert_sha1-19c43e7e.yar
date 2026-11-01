rule Sightlines_signer_cert_sha1_19c43e7e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-19c43e7e"
        date = "2026-10-27"
        campaign = "signer_cert_sha1-19c43e7e"
        family = ""
        hash = "09499e186cf0e434ffa17ad153aa9a66d6048c54a2c03b823e2a06c49d9affe4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-19c43e7e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_http://www.microsoft.com/pkiops/crl/Microsoft%20ID%20Verified%20Code%20Signing%20PCA%202021.crl0}" ascii
        $s1 = "ahttp://www.microsoft.com/pkiops/certs/Microsoft%20ID%20Verified%20Code%20Signing%20PCA%202021.crt0" ascii
        $s2 = "Copyright 1998-2026 The OpenSSL Authors. All rights reserved." wide
        $s3 = "Xhttp://www.microsoft.com/pkiops/certs/Microsoft%20ID%20Verified%20CS%20AOC%20CA%2003.crt0T" ascii
        $s4 = "Vhttp://www.microsoft.com/pkiops/crl/Microsoft%20ID%20Verified%20CS%20AOC%20CA%2003.crl0t" ascii
        $s5 = "\"Microsoft ID Verified CS AOC CA 030" ascii
        $s6 = "260611073243Z0|1" ascii
        $s7 = "310326181132Z0Z1" ascii
        $s8 = "260608073243Z" ascii
        $s9 = "260326181132Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10477040 and 10 of them
}
