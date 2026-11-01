rule Sightlines_tlsh_f45cf165_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f45cf165"
        date = "2026-11-01"
        campaign = "tlsh-f45cf165"
        family = ""
        hash = "0a274d9ee2f3ceef05af7f4527fc450c44d7b27f48aa7c78cab90c6500ceb675"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f45cf165.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".eh_poolATI" ascii
        $s1 = "p L3P0L3PXH" ascii
        $s2 = "glibcxx.SH" ascii
        $s3 = "H3x@H3xhM1" ascii
        $s4 = "L3@8L3@`M1" ascii
        $s5 = "L3`PL3H8H" ascii
        $s6 = "L3hPL3hxL3" ascii
        $s7 = "D$0H+D$8" ascii
        $s8 = "tnAUATUH" ascii
        $s9 = "mAVAUATI" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}
