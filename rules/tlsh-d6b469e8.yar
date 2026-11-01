rule Sightlines_tlsh_d6b469e8_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d6b469e8"
        date = "2026-11-01"
        campaign = "tlsh-d6b469e8"
        family = "mirai"
        hash = "33ea1f70372c9a472bea64f68dba54a92c392abb09219a60af8db246495b53e7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d6b469e8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s2 = "e365`70;9ag:<$ef1=d?2>T" ascii
        $s3 = "509=:efg`" ascii
        $s4 = "5::=1fdef" ascii
        $s5 = ".-50efg`" ascii
        $s6 = "$662*7!E" ascii
        $s7 = "7<5:3191" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 8 of them
}
