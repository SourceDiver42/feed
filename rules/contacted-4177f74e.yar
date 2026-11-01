rule Sightlines_contacted_4177f74e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-4177f74e"
        date = "2026-11-01"
        campaign = "contacted-4177f74e"
        family = "mirai"
        hash = "3f8028b2d52bab13a15d815a82cc8b8447187d6b2d28fa31a874d66cac429c2d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-4177f74e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "r\\8Tl$lp$8W_" ascii
        $s1 = "++wU3UD3\"\"" ascii
        $s2 = "<wQ\"B?TA" ascii
        $s3 = "lXa\\x}6T" ascii
        $s4 = "rj<s.yN>" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 24430912 and 5 of them
}
