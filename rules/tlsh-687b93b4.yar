rule Sightlines_tlsh_687b93b4_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-687b93b4"
        date = "2026-10-28"
        campaign = "tlsh-687b93b4"
        family = "mirai"
        hash = "0c83f3ce10f00774ab4ce0163b21e12337fd462927c7aac9749f5ffd525691ac"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-687b93b4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s2 = "e365`70;9ag:<$ef1=d?2>T" ascii
        $s3 = "509=:efg`" ascii
        $s4 = "5::=1fdef" ascii
        $s5 = ".-50efg`" ascii
        $s6 = "9t$$tBPPj" ascii
        $s7 = "$662*7!E" ascii
        $s8 = "7<5:3191" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}
