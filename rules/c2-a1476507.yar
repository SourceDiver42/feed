rule Sightlines_c2_a1476507_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-a1476507"
        date = "2026-10-28"
        campaign = "c2-a1476507"
        family = "mirai"
        hash = "0c83f3ce10f00774ab4ce0163b21e12337fd462927c7aac9749f5ffd525691ac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-a1476507.json"
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
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}
