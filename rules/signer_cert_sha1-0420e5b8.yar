rule Sightlines_signer_cert_sha1_0420e5b8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-0420e5b8"
        date = "2026-11-01"
        campaign = "signer_cert_sha1-0420e5b8"
        family = ""
        hash = "5b13c58fbf6eb3073f7a906cebc9148609eece5c451324541acfdc8ef6b45f3f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-0420e5b8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Yhttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crl0w" ascii
        $s1 = "[http://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "'Microsoft Windows Code Signing PCA 20240" ascii
        $s3 = "Microsoft Corporation100." ascii
        $s4 = "350623220401Z0_1" ascii
        $s5 = "260528185511Z0t1" ascii
        $s6 = "240808213623Z" ascii
        $s7 = "250529185511Z" ascii
        $s8 = "500507+5052770" ascii
        $s9 = "_0Oio=NA" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9488080 and 10 of them
}
