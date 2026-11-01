rule Sightlines_signer_cert_sha1_2cf78abf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-2cf78abf"
        date = "2026-10-22"
        campaign = "signer_cert_sha1-2cf78abf"
        family = ""
        hash = "0f885b509a685d2bbfa652fed26b5fb31d88fbdab0a978c641d1c7b8aa460aa9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-2cf78abf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "260515184909Z0t1" ascii
        $s1 = "230217+5049170" ascii
        $s2 = "230889+5049200" ascii
        $s3 = "260515182606Z0" ascii
        $s4 = "250515184909Z" ascii
        $s5 = "250515182606Z" ascii
        $s6 = "G!2Wv[.O" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1115456 and 7 of them
}
