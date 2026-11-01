rule Sightlines_tlsh_86ea993a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-86ea993a"
        date = "2026-10-21"
        campaign = "tlsh-86ea993a"
        family = ""
        hash = "b76cc467389add76c92b8db4d6a3eba12f7403d364ad3425b34e5798323306fd"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-86ea993a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1u1$)&u+17u)qdE" ascii
        $s1 = "wq\"x{JDJK" ascii
        $s2 = "-0+1prp|" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 3 of them
}
