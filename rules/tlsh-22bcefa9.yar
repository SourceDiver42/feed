rule Sightlines_tlsh_22bcefa9_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-22bcefa9"
        date = "2026-11-01"
        campaign = "tlsh-22bcefa9"
        family = "mirai"
        hash = "065092a744c8d49931a99771e831b38d86c3b344f5c0221ac9d3de18d9837163"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-22bcefa9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Self Rep Fucking NeTiS and Thisity 0n Ur FuCkInG FoReHeAd We BiG L33T HaxErS" ascii
        $s1 = " /x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9" ascii
        $s2 = "A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9" ascii
        $s3 = "e365`70;9ag:<$ef1=d?2>T" ascii
        $s4 = "?/dev/null" ascii
        $s5 = "509=:efg`" ascii
        $s6 = "5::=1fdef" ascii
        $s7 = ".-50efg`" ascii
        $s8 = "$662*7!E" ascii
        $s9 = "7<5:3191" ascii
        $s10 = "}CSx}e[x" ascii
        $s11 = "}e[x}CSx" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
