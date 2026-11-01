rule Sightlines_tlsh_dd9cd5ef_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dd9cd5ef"
        date = "2026-10-30"
        campaign = "tlsh-dd9cd5ef"
        family = "mirai"
        hash = "16f650696596a2b46a317d17e8c9b7e6a1dfc65d843a50769b87dd3944417d7e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dd9cd5ef.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" ascii
        $s1 = "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B" ascii
        $s2 = "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5" ascii
        $s3 = "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551" ascii
        $s4 = "/businessCategory=" ascii
        $s5 = "/favouriteDrink=" ascii
        $s6 = "/jurisdictionST=" ascii
        $s7 = "/jurisdictionC=" ascii
        $s8 = "/serialNumber=" ascii
        $s9 = "/postalCode=" ascii
        $s10 = "/userid=" ascii
        $s11 = "/street=" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
