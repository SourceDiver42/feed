rule Sightlines_tlsh_ed5b872b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ed5b872b"
        date = "2026-11-01"
        campaign = "tlsh-ed5b872b"
        family = ""
        hash = "8f82c3c20a9051b6876612a28cbc353c8ea61532a4e6a343764854ce4d6f2a91"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ed5b872b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "L$TSVWUR" ascii
        $s1 = "D$HkD$0:" ascii
        $s2 = "D$P9D$Lu" ascii
        $s3 = "D$H9D$Du" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 4 of them
}
