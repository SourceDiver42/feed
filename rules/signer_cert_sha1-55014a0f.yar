rule Sightlines_signer_cert_sha1_55014a0f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign signer_cert_sha1-55014a0f"
        date = "2026-10-30"
        campaign = "signer_cert_sha1-55014a0f"
        family = ""
        hash = "052ad6a20d375957e82aa6a3c441ea548d89be0981516ca7eb306e063d5027f4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/signer_cert_sha1-55014a0f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "20250118131503Z0w0=" ascii
        $s1 = "250820192644Z0t1" ascii
        $s2 = "230889+5027690" ascii
        $s3 = "20250117131503Z" ascii
        $s4 = "250820195927Z0" ascii
        $s5 = "240822195927Z" ascii
        $s6 = "230217+5027230" ascii
        $s7 = "240822192644Z" ascii
        $s8 = "/iAMy!X~" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1171744 and 9 of them
}
