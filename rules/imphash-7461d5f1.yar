rule Sightlines_imphash_7461d5f1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-7461d5f1"
        date = "2026-10-30"
        campaign = "imphash-7461d5f1"
        family = ""
        hash = "04ce42fa815b84480b259d4140c9e2d070e94a5d7480e3f020042892c8ac33a5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-7461d5f1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$_Func_impl_no_alloc@V<lambda_06358633a4c44273907fcb2e28171d6d>@@V?$optional@_J@std@@PEAUHWND__" ascii
        $s1 = ".?AV?$_Func_impl_no_alloc@V<lambda_7f1a937f2a091b23c858f0d24ff7078e>@@XPEBE_KV?$function@$$A6AXPEBE_" ascii
        $s2 = ".?AV?$_Func_impl_no_alloc@V<lambda_e037921e1ce5787a4133e127eb1233d0>@@XPEBE_KV?$function@$$A6AXPEBE_" ascii
        $s3 = ".?AV?$_Func_impl_no_alloc@V<lambda_ebf987130683dbcfdf8a9e6741ac0e61>@@V?$unique_ptr@U?$StreamHandler" ascii
        $s4 = ".?AV?$_Func_impl_no_alloc@V<lambda_9f510eb0755469b909feb09f2bfcbb66>@@V?$unique_ptr@U?$StreamHandler" ascii
        $s5 = ".?AV?$_Func_impl_no_alloc@V<lambda_c0c1625216aed95fbf5e7766576c21bb>@@XAEBV?$MethodCall@VEncodableVa" ascii
        $s6 = ".?AV?$_Ref_count_resource@PEAUFlutterDesktopMessenger@@P6AXPEAU1@@Z@std@@" ascii
        $s7 = ".?AV?$_Func_base@XAEBV?$MethodCall@VEncodableValue@flutter@@@flutter@@V?$unique_ptr@V?$MethodResult@" ascii
        $s8 = ".?AV<lambda_06358633a4c44273907fcb2e28171d6d>@@" ascii
        $s9 = ".?AV?$_Func_base@V?$optional@_J@std@@PEAUHWND__@@I_K_J@std@@" ascii
        $s10 = "?_New_Locimp@_Locimp@locale@std@@CAPEAV123@AEBV123@@Z" ascii
        $s11 = "?_Locimp_Addfac@_Locimp@locale@std@@CAXPEAV123@PEAVfacet@23@_K@Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
