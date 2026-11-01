rule Sightlines_tlsh_83ffefec_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-83ffefec"
        date = "2026-11-01"
        campaign = "tlsh-83ffefec"
        family = "mirai"
        hash = "191c0859e16a94f0188276105ba5d1c07d3db578a994da12f4f876a66dc150b8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-83ffefec.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 3.94 Copyright (C) 1996-2017 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "(!PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "hW;U`Do4R" ascii
        $s4 = "M~Lp2QRff" ascii
        $s5 = "6X@f/NGH" ascii
        $s6 = "DT|UEJlC" ascii
        $s7 = "Ztg6k\"fJ" ascii
        $s8 = "&ZZDJ8}1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}
