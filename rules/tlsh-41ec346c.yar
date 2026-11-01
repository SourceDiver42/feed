rule Sightlines_tlsh_41ec346c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-41ec346c"
        date = "2026-10-22"
        campaign = "tlsh-41ec346c"
        family = ""
        hash = "855dc4b6ae1f10a5bb4d7ee450e536020fe495079f1a2f1b39a334ec03a68150"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-41ec346c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1u1$)&u+17u)qdE" ascii
        $s1 = "wq\"x{JDJK" ascii
        $s2 = "TKih8Lkh8" ascii
        $s3 = "-0+1prp|" ascii
        $s4 = "kjk8Ki(8" ascii
        $s5 = "Lih8mih8" ascii
        $s6 = "hi8+hi8_" ascii
        $s7 = "lih8Mih8" ascii
        $s8 = "jjj8*i(8" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}
