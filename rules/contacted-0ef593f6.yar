rule Sightlines_contacted_0ef593f6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-0ef593f6"
        date = "2026-10-31"
        campaign = "contacted-0ef593f6"
        family = ""
        hash = "2bdd795ab5ffd8a9f25c512e812ca604091229688eb114ae3be5796197dcb015"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-0ef593f6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 3.96 Copyright (C) 1996-2020 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "GCC: (GNU) 4.8.5 20150623(Red" ascii
        $s3 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s4 = "(`& hIlxRr$/iIO" ascii
        $s5 = "build-id%ABI-Pg" ascii
        $s6 = "5#>CQ;t 2U01UJ" ascii
        $s7 = "mCg6YD|Y\\C]UNK" ascii
        $s8 = "runtime/cgo: " ascii
        $s9 = "amdhsa.kernels" ascii
        $s10 = "&-8P Tc58H0bk" ascii
        $s11 = "x86_rd-(void)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 18489600 and 12 of them
}
