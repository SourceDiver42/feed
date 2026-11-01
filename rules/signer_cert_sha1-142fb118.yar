rule Sightlines_signer_cert_sha1_142fb118_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-142fb118"
        date = "2026-10-22"
        campaign = "signer_cert_sha1-142fb118"
        family = ""
        hash = "184146852727a9db4eea06178716bec3cdbb1015c911f6b0f915b184ad7775b2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-142fb118.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "260515184910Z0t1" ascii
        $s1 = "230217+5049070" ascii
        $s2 = "230889+5049100" ascii
        $s3 = "260515182607Z0" ascii
        $s4 = "250515182607Z" ascii
        $s5 = "250515184910Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1107104 and 6 of them
}
