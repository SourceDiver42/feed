rule Sightlines_rich_header_hash_6a7fcf10_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-6a7fcf10"
        date = "2026-10-15"
        campaign = "rich_header_hash-6a7fcf10"
        family = ""
        hash = "0e823fe2692ba740b73c8f0cc47f2d732ede3b17dd7d268219e7e1611b9ae239"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-6a7fcf10.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "tUH9\\$htN9\\$`~H" ascii
        $s1 = "H USVWATAUAVAWH" ascii
        $s2 = " BD8d$`t5M" ascii
        $s3 = "0uNH9|$@tG" ascii
        $s4 = "D$ H5J)n(H" ascii
        $s5 = "D$@H5`fZ8H" ascii
        $s6 = "D$pH5*UBoH" ascii
        $s7 = "D$pH50B|ZH" ascii
        $s8 = "HcD$`Hc\\$8H" ascii
        $s9 = "]ofD9\"t#H" ascii
        $s10 = "mKD9s ~yI" ascii
        $s11 = "xJL9l$PtC" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4399140 and 12 of them
}
