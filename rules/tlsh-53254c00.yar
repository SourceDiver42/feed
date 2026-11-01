rule Sightlines_tlsh_53254c00_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-53254c00"
        date = "2026-10-30"
        campaign = "tlsh-53254c00"
        family = ""
        hash = "abf3bd07946b7a2f1ce7a5a770b845a64b02773150ab88a749f82aea06e70b9e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-53254c00.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "tbB-|yE:NEjbC" ascii
        $s4 = "T\"qhFO8a}w" ascii
        $s5 = "e?S~o,57y" ascii
        $s6 = "5p'Q>yRP" ascii
        $s7 = "8t/fPkXg" ascii
        $s8 = "UqHY_TZB" ascii
        $s9 = "bA5&C8'9" ascii
        $s10 = "fm#ZhJkH" ascii
        $s11 = "tlP[Ur, " ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
