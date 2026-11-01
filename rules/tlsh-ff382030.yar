rule Sightlines_tlsh_ff382030_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ff382030"
        date = "2026-11-01"
        campaign = "tlsh-ff382030"
        family = ""
        hash = "0fbc3a79711c7e73a66b97f58ab9e643841d1580eed249c37481cf2922b5c5ce"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ff382030.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\Registry\\Machine\\Software\\Classes\\" wide
        $s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes" wide
        $s2 = "\\REGISTRY\\USER" wide
        $s3 = "Wow6432Node" wide
        $s4 = "t$ WATAUE3" ascii
        $s5 = "G0H9G8u_A" ascii
        $s6 = "H SUVWATH" ascii
        $s7 = "6T{tmF M" ascii
        $s8 = "~Hx1UnBZ" ascii
        $s9 = "&]p}8W8J" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9678848 and 10 of them
}
