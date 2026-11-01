rule Sightlines_contacted_d0c7d75d_salatstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-d0c7d75d"
        date = "2026-11-01"
        campaign = "contacted-d0c7d75d"
        family = "salatstealer"
        hash = "02fa9c7b88f443b451e7f03bdb723558cc8db7c35eee130e3fd17429813b00c4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-d0c7d75d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GBZAP-PACK-UNIQUE" ascii
        $s1 = "KbpxF9v|1<`J~|" ascii
        $s2 = "{}z4:RHGd,X,NB" ascii
        $s3 = "'i]m&yNefvj}" ascii
        $s4 = "BzawNgE[Q|K`" ascii
        $s5 = "Gz4!d|#D<Ogb" ascii
        $s6 = "im|5?2K0l}\\4" ascii
        $s7 = "Cneq^6!+KezX" ascii
        $s8 = "F:[`qIQAC>tQ" ascii
        $s9 = "!amb)&zg-s3" ascii
        $s10 = "=:0<,8OADcK" ascii
        $s11 = "MI{O*qR%!h5" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7186108 and 12 of them
}
