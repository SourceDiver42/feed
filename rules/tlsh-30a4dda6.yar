rule Sightlines_tlsh_30a4dda6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-30a4dda6"
        date = "2026-10-30"
        campaign = "tlsh-30a4dda6"
        family = ""
        hash = "50e191fa03037a3f31c478da563e205d92355c3ff989299dcf40407ac42a5f32"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-30a4dda6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "~M[f8,rvO" ascii
        $s4 = "J59p]o|[" ascii
        $s5 = "dV'r^c_S" ascii
        $s6 = "B2v>B)62" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}
