rule Sightlines_tlsh_18a0c52c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-18a0c52c"
        date = "2026-10-18"
        campaign = "tlsh-18a0c52c"
        family = ""
        hash = "2ff9ff956650c6180b0f64bdf389e36cc4eb4eb4fc28cd6be716f43c1b083a06"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-18a0c52c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "GCC: (Ubuntu 11.4.0-1u" ascii
        $s4 = "hk@hIBC_2.3.4nKVp" ascii
        $s5 = "pthread_mutex_loc" ascii
        $s6 = "GLOBAL_OFFSET_TABL" ascii
        $s7 = "3D3K3M*3O3Y3[6$6%" ascii
        $s8 = "Sjuantech54Fl" ascii
        $s9 = "inc9recLfaileC" ascii
        $s10 = " SOCKS5 on :%d" ascii
        $s11 = "feUco>47450</" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
