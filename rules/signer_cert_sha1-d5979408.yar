rule Sightlines_signer_cert_sha1_d5979408_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-d5979408"
        date = "2026-10-30"
        campaign = "signer_cert_sha1-d5979408"
        family = ""
        hash = "03d233dbace599168eaffec823de6ed7beec8c2a4ebfe9b8a3d8e042a59af3ba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-d5979408.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Xhttp://www.microsoft.com/pkiops/certs/Microsoft%20ID%20Verified%20CS%20AOC%20CA%2001.crt0-" ascii
        $s1 = "Vhttp://www.microsoft.com/pkiops/crl/Microsoft%20ID%20Verified%20CS%20AOC%20CA%2001.crl0" ascii
        $s2 = "\"Microsoft ID Verified CS AOC CA 010" ascii
        $s3 = "FBuilt: Release_v3.12.10_20250408.0" wide
        $s4 = "260413173154Z0Z1" ascii
        $s5 = "250411010724Z0|1" ascii
        $s6 = "210413173154Z" ascii
        $s7 = "250408010724Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 13890544 and 8 of them
}
