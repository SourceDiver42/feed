rule Sightlines_tlsh_ab89c663_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ab89c663"
        date = "2026-10-22"
        campaign = "tlsh-ab89c663"
        family = "mirai"
        hash = "04bdee4f273e2b4d2e1f05c9babfd772f19f7f92eadb6221c42254d683ee2963"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ab89c663.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1u1$)&u+17u)qdE" ascii
        $s1 = "wq\"x{JDJK" ascii
        $s2 = "-0+1prp|" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 3 of them
}
