rule Sightlines_imphash_3c5e4aaa_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-3c5e4aaa"
        date = "2026-10-16"
        campaign = "imphash-3c5e4aaa"
        family = ""
        hash = "184146852727a9db4eea06178716bec3cdbb1015c911f6b0f915b184ad7775b2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-3c5e4aaa.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "svbfloat16" ascii
        $s1 = "svfloat16" ascii
        $s2 = "svfloat32" ascii
        $s3 = "svfloat64" ascii
        $s4 = "svuint16" ascii
        $s5 = "svuint32" ascii
        $s6 = "svuint64" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 7 of them
}
