rule Sightlines_tlsh_c642c5f9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c642c5f9"
        date = "2026-10-30"
        campaign = "tlsh-c642c5f9"
        family = ""
        hash = "00acdf1a6e53274103bad33d0e3af7e4222b3c96a464045b3c04e24b6db39d90"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c642c5f9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "(!PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "ovD;-Tc$5G@" ascii
        $s4 = "\\N6E<A>Fn" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 5 of them
}
