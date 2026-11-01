rule Sightlines_tlsh_964cee94_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-964cee94"
        date = "2026-10-29"
        campaign = "tlsh-964cee94"
        family = ""
        hash = "2a878ae3dae7eeee4efd2be95ba8957c8a097d25f57cca59dd6976b1e81c35e8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-964cee94.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "1u1$)&u+17u)qdE" ascii
        $s1 = "UVRSQWPj%" ascii
        $s2 = "D$4jPj#UW" ascii
        $s3 = "t$(RRUVRj" ascii
        $s4 = "-0+1prp|" ascii
        $s5 = "D$\\3D$Lx" ascii
        $s6 = "D$d3D$,x" ascii
        $s7 = "L$(3L$Lx" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}
