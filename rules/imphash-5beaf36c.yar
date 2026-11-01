rule Sightlines_imphash_5beaf36c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-5beaf36c"
        date = "2026-10-30"
        campaign = "imphash-5beaf36c"
        family = ""
        hash = "0c42127c2e483ff00d5525e71cf53c75d9768421368623c38ea758181672ffba"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-5beaf36c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$_Func_impl_no_alloc@V<lambda_7f1a937f2a091b23c858f0d24ff7078e>@@XPEBE_KV?$function@$$A6AXPEBE_" ascii
        $s1 = ".?AV?$_Func_impl_no_alloc@V<lambda_a7e5c5c9b6b04193c20a21573dea4e4a>@@XPEBE_K@std@@" ascii
        $s2 = ".?AV?$_Ref_count_resource@PEAUFlutterDesktopMessenger@@P6AXPEAU1@@Z@std@@" ascii
        $s3 = ".?AV?$_Func_base@XAEBV?$MethodCall@VEncodableValue@flutter@@@flutter@@V?$unique_ptr@V?$MethodResult@" ascii
        $s4 = ".?AV?$_Func_base@V?$optional@_J@std@@PEAUHWND__@@I_K_J@std@@" ascii
        $s5 = "?_New_Locimp@_Locimp@locale@std@@CAPEAV123@AEBV123@@Z" ascii
        $s6 = "?_Locimp_Addfac@_Locimp@locale@std@@CAXPEAV123@PEAVfacet@23@_K@Z" ascii
        $s7 = ".?AV?$_Func_base@XPEBE_KV?$function@$$A6AXPEBE_K@Z@std@@@std@@" ascii
        $s8 = "?_Raise_handler@std@@3P6AXAEBVexception@stdext@@@ZEA" ascii
        $s9 = "?_Init@locale@std@@CAPEAV_Locimp@12@_N@Z" ascii
        $s10 = ".?AV<lambda_7f1a937f2a091b23c858f0d24ff7078e>@@" ascii
        $s11 = "Unknown type in StandardCodecSerializer::ReadValueOfType: " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
