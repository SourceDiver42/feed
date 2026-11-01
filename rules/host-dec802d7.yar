rule Sightlines_host_dec802d7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-dec802d7"
        date = "2026-11-01"
        campaign = "host-dec802d7"
        family = "mirai"
        hash = "c36da87c2bfff2ec8d93228ca0f017e9e1f942c74a0d1387bcd6659c7418e8d0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-dec802d7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s1 = "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A" ascii
        $s2 = "e365`70;9ag:<$ef1=d?2>T" ascii
        $s3 = "$662*7!E" ascii
    condition:
        filesize < 1048576 and 4 of them
}
