rule Sightlines_signer_cert_sha1_b0e443fb_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-b0e443fb"
        date = "2026-10-16"
        campaign = "signer_cert_sha1-b0e443fb"
        family = ""
        hash = "052a2258a185f4c858326ff1a5754b2c4c2bf680c12ebf30a3c2b2b9c1af8f68"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-b0e443fb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<http://cert.ssl.com/SSLcom-SubCA-CodeSigning-RSA-4096-R1.cer0 " ascii
        $s1 = "Ehttp://www.ssl.com/repository/SSLcomRootCertificationAuthorityRSA.crt0 " ascii
        $s2 = "+SSL.com Code Signing Intermediate CA RSA R10" ascii
        $s3 = "(SSL.com Root Certification Authority RSA0" ascii
        $s4 = "https://www.ssl.com/repository0" ascii
        $s5 = "Pelican Finland Holding Oy0" ascii
        $s6 = "Pelican Self Storage1#0!" ascii
        $s7 = "SSL Corporation110/" ascii
        $s8 = "270826130109Z0v1" ascii
        $s9 = "410212173939Z0|1" ascii
        $s10 = "341112185005Z0n1" ascii
        $s11 = "341112185005Z0s1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 24638128 and 12 of them
}
