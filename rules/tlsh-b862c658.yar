rule Sightlines_tlsh_b862c658_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b862c658"
        date = "2026-10-30"
        campaign = "tlsh-b862c658"
        family = ""
        hash = "01ad58ff981d0f5d113f511a4e74367590086c7ab947335049d3df85c5822449"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b862c658.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "(!PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "!LdH #tq" ascii
        $s4 = "Y`R'ncF~" ascii
        $s5 = "j8r<k6%f" ascii
        $s6 = "zbO2_)7\\" ascii
        $s7 = "41UMy*ll" ascii
        $s8 = "n$nua1FE" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}
