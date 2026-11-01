rule Sightlines_tlsh_46922055_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-46922055"
        date = "2026-10-30"
        campaign = "tlsh-46922055"
        family = "remcos"
        hash = "1a338cc60ab238a3fd84671c4ad1523c0c8ee3c6bdd6889859d997c101fecc24"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-46922055.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "0/r','Underflow\\x20exception\\x20flag.','3256288iSzOpZ','W:_dh165[15:0]\\x20{kz},\\x20m16','64uPgome','" ascii
        $s1 = "ag.','VAES','MCOMMIT','W:_dh165\\x20{kz},_dh165[127:16],_dh165[15:0]/m16,ib/ub\\x20{sae}','Similar\\x20" ascii
        $s2 = "512_ERI','vucomish','3DNOW','_dh165.128.NP.MAP5.W0\\x205D\\x20/r','Interrupt\\x20enable\\x20flag.','\\u26" ascii
        $s3 = "','vrndscaleph','X87SW.EXC','_dh165.128.66.MAP6.W0\\x2042\\x20/r','vmulsh','string','_dh165.LIG.NP.0F3" ascii
        $s4 = "x20level.','2vsWdzL','LAHFSAHF','CreateTextFile','W:zmm\\x20{kz},\\x20zmm/m512/b16\\x20{sae}','MONITORX" ascii
        $s5 = "p\\x20flag.','_dh165.256.NP.0F3A.W0\\x2066\\x20/r\\x20ib','_dh165.DENORMAL','X87SW.C2','Stack\\x20fault.'" ascii
        $s6 = "','Exception\\x20flag.','W:k\\x20{k},\\x20zmm/m512/b16,\\x20ib/ub','_dh165.128.66.MAP5.WIG\\x206E\\x20/r'," ascii
        $s7 = "ble\\x20bit.','_dh165.256.66.MAP6.W0\\x204E\\x20/r','W:_dh165[15:0]\\x20{kz},\\x20r32[15:0]/m16','PCLMULQ" ascii
        $s8 = "2026\\x20/r\\x20ib','_dh165.LIG.66.MAP6.W0\\x202D\\x20/r','XSAVES','_dh165.ZERO_DIVIDE','Virtual\\x20inte" ascii
        $s9 = "ITE','ENCLV','UINTR','RDTSC','_dh165.512.NP.0F3A.W0\\x2056\\x20/r\\x20ib','Lock','Control','reverse','D" ascii
        $s10 = ",'X87SW.INVALID_OP','random','_dh165.512.66.MAP6.W0\\x20BE\\x20/r','_dh165.F2.0F38.W0\\x2049\\x20/r','_d" ascii
        $s11 = "0\\x20BC\\x20/r','_dh165.256.NP.MAP5.W0\\x205F\\x20/r','vgetexpph','Nested\\x20task\\x20flag.','RVMI-T1S'," ascii
    condition:
        filesize < 11726436 and 12 of them
}
