rule Sightlines_tlsh_417d2328_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-417d2328"
        date = "2026-10-18"
        campaign = "tlsh-417d2328"
        family = ""
        hash = "1fac02a405615d392e3ca0b0e706f3f27c5b64dcc1e690d175c37fe0f71742b3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-417d2328.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.22 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = " !9999\"#$%9999&'()9999*+,-9999./0199992345999967899999:;<=9999>?@A9999BCDE9999FGHI9999JKLM9999NOPQ99" ascii
        $s3 = "MNOrrrrPRTUrrrrVWYZrrrr[\\_`rrrrabcdrrrrefhi9rrrjk" ascii
        $s4 = "(!PROT_EXEC|PROT_WRITE failed." ascii
        $s5 = "9999 \"$%9999&/56999979:<9999DGHI9999_`ab9999c" ascii
        $s6 = "'\\/`iMiM7d?hiMiMGlOpiMiMWt_x" ascii
        $s7 = "sion.skip_lock_after_retrl" ascii
        $s8 = "GCC: (Ubuntu 12.4.0-2u" ascii
        $s9 = "Wo3hJHr5jfDKYmvLOyT" ascii
        $s10 = "'Wr%C345%Wr%67`%Wr89." ascii
        $s11 = "_X3.4-1968//TR\"LI" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
