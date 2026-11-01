rule Sightlines_tlsh_a4217816_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a4217816"
        date = "2026-10-30"
        campaign = "tlsh-a4217816"
        family = ""
        hash = "10290f113204c92214abfc94fcf64a92823ee2a4436e286bc67193884604ad57"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a4217816.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "nU01Z!Adu]-s;Eb}Za" ascii
        $s1 = "U,o[iUimaucvXYVPf" ascii
        $s2 = "fabric.mod.jsonPK" ascii
        $s3 = "f`u5\\K6q155T@XV" ascii
        $s4 = "8l9]o#5tYHnaK\"" ascii
        $s5 = "OW:xI>Y\"^Ow4xIa" ascii
        $s6 = "B$'$U<BMwaGICL" ascii
        $s7 = "&c<Z9dIieYJH." ascii
        $s8 = "C1Yz_}d9w=?m8" ascii
        $s9 = "N2dM>\\iB/3rFA" ascii
        $s10 = "H?LH?PH?TH?XH?\\H?fH" ascii
        $s11 = "B*ItAa=?I:%nt" ascii
    condition:
        filesize < 5891420 and 12 of them
}
