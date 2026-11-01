rule Sightlines_tlsh_fa4b622d_amadey
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fa4b622d"
        date = "2026-10-26"
        campaign = "tlsh-fa4b622d"
        family = "amadey"
        hash = "04ef642ea5f51c774c5f879827f989c5070efd2767c4d7d4022b1111ac6f7a94"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fa4b622d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$_Fake_no_copy_callable_adapter@A6GXPAUConnexionDetails@@@ZAAPAU1@@std@@" ascii
        $s1 = ".?AV?$_ExceptionPtr_static@Vbad_alloc@std@@@?A0xb4bb966e@@" ascii
        $s2 = ".?AV<lambda_9de88c4009318ef1202283857f94e673>@@" ascii
        $s3 = ".?AV?$_ExceptionPtr_static@Vbad_exception@std@@@?A0xb4bb966e@@" ascii
        $s4 = ".?AV<lambda_cf64729cb90f65090849ddab3f3d5e68>@@" ascii
        $s5 = "powershell -Command Expand-Archive -Path '" ascii
        $s6 = ".?AV_ExceptionPtr_normal@?A0xb4bb966e@@" ascii
        $s7 = ".?AV<lambda_5e5ab22ea98f4361dbf159481d01f54d>@@" ascii
        $s8 = ".?AVstl_condition_variable_win7@details@Concurrency@@" ascii
        $s9 = ".?AV<lambda_eb87dfd73f857f44e1a351ea42ce2b34>@@" ascii
        $s10 = ".?AV<lambda_0456396a71e3abd88ede77bdd2823d8e>@@" ascii
        $s11 = ".?AVstl_condition_variable_vista@details@Concurrency@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
