rule Sightlines_imphash_c257812e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-c257812e"
        date = "2026-10-30"
        campaign = "imphash-c257812e"
        family = ""
        hash = "a27f73fc68cc57818495ced810ae6bf21fa9fa26ac8f6c9df0dfc8a1458a841f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-c257812e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$_Func_impl_no_alloc@V<lambda_25d3896e8ef8b6c96b2447515601dd6c>@@XAEBVTrayIconEvent@nativeapi@@" ascii
        $s1 = ".?AV?$_Func_impl_no_alloc@V<lambda_48413c09f659d914c3d5cf12bd9da65e>@@XAEBVWindowDragEvent@nativeapi" ascii
        $s2 = ".?AV?$_Func_impl_no_alloc@V<lambda_f57a2f4f1480e877f41603cccfb25239>@@V?$optional@_J@std@@PEAUHWND__" ascii
        $s3 = ".?AV?$_Func_impl_no_alloc@V<lambda_4e7f7cd9c7fab1409d5211f2b25264a0>@@XAEBVDragSourceEvent@nativeapi" ascii
        $s4 = ".?AV?$_Func_impl_no_alloc@V<lambda_c8fd7b4dfc00a19c51ff182754a7205c>@@XAEBVDropTargetEvent@nativeapi" ascii
        $s5 = ".?AV?$_Func_impl_no_alloc@V<lambda_4942f08d62feb30f2ac0f0a4d8b15e8f>@@V?$optional@_J@std@@PEAUHWND__" ascii
        $s6 = ".?AV?$_Func_impl_no_alloc@V<lambda_a5b84cc055a4d9604235b78a4293f81e>@@XAEBVDisplayEvent@nativeapi@@@" ascii
        $s7 = ".?AV?$_Func_impl_no_alloc@V<lambda_214d660b748e67ef51530dea3e1b438f>@@XAEBVMenuEvent@nativeapi@@@std" ascii
        $s8 = ".?AV?$_Func_impl_no_alloc@V<lambda_40ae683a230daf887f4516d83637a1ff>@@V?$optional@_J@std@@PEAUHWND__" ascii
        $s9 = ".?AV?$_Func_impl_no_alloc@V<lambda_36811539b42d23eecb5ec5572d26e122>@@V?$optional@_J@std@@PEAUHWND__" ascii
        $s10 = ".?AV?$_Func_impl_no_alloc@V<lambda_06d24ead2778dfd12af737d545eece76>@@V?$optional@_J@std@@PEAUHWND__" ascii
        $s11 = ".?AV?$_Func_impl_no_alloc@V<lambda_49bfa564f4ea9210d72e815f9ccb9b2d>@@XAEBVMenuEvent@nativeapi@@@std" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1350656 and 12 of them
}
