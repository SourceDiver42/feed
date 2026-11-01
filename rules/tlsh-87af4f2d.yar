rule Sightlines_tlsh_87af4f2d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-87af4f2d"
        date = "2026-10-30"
        campaign = "tlsh-87af4f2d"
        family = ""
        hash = "105e42b8e1cfbe3a7baba5349ceff65bbee9f2707bc92738576f276824623a2b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-87af4f2d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "Ts6m'q:#EB" ascii
        $s4 = "*PiX5[#4" ascii
        $s5 = "H-wy&3J)" ascii
        $s6 = "Y&3tE{Ar" ascii
        $s7 = "`hu8RLXK" ascii
        $s8 = "vB]'VGrj" ascii
        $s9 = "O5O~@i_N" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 10 of them
}
