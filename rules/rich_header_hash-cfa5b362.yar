rule Sightlines_rich_header_hash_cfa5b362_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-cfa5b362"
        date = "2026-10-30"
        campaign = "rich_header_hash-cfa5b362"
        family = ""
        hash = "1dcc54cd1aa45779e487f0dd46c96280c70c9ea370416ea15a11be92b4318017"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-cfa5b362.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "{7>8cE>kV#)WzH" ascii
        $s1 = "Sn_bC~Ora\\%" ascii
        $s2 = "#GK*5A?^CCM" ascii
        $s3 = "aJ1l{[}3c" ascii
        $s4 = "%LI%O*Oo9" ascii
        $s5 = "M S#7YQ0" ascii
        $s6 = "M#S:7PQ9" ascii
        $s7 = "i3VM>]}W" ascii
        $s8 = "q3ZM\"]3W" ascii
        $s9 = "zIsSs??7" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1208400 and 6 of them
}
