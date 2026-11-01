rule Sightlines_tlsh_e9c8dfe9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e9c8dfe9"
        date = "2026-10-30"
        campaign = "tlsh-e9c8dfe9"
        family = ""
        hash = "3d76d4c624a030fe28eb57702f03a18e2745acc2969ad27c3d4712be96ebfb26"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e9c8dfe9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $" ascii
        $s1 = "$Info: This file is packed with the UPX executable packer http://upx.sf.net $" ascii
        $s2 = "PROT_EXEC|PROT_WRITE failed." ascii
        $s3 = "5u<[!NL!Frk" ascii
        $s4 = "RS4\\CL&Zrl" ascii
        $s5 = "h`~kRv<}uT" ascii
        $s6 = "+Gwe%7}WI" ascii
        $s7 = "j=bZFV?FN" ascii
        $s8 = "LnDwVtk[" ascii
        $s9 = "MHJ_fh7w" ascii
        $s10 = "MqT}xmi[" ascii
        $s11 = "S\\Ij`Q43" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
