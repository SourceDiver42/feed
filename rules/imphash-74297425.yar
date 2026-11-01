rule Sightlines_imphash_74297425_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-74297425"
        date = "2026-10-26"
        campaign = "imphash-74297425"
        family = ""
        hash = "9ddb5cfa4a64771fbed9b74c1bba90c9e84d1d24d5cb56ed2e3472b17f59cb37"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-74297425.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "INSERT INTO %s.sqlite_schema SELECT*FROM \"%w\".sqlite_schema WHERE type IN('view','trigger') OR(type=" ascii
        $s1 = "SELECT'INSERT INTO %s.'||quote(name)||' SELECT*FROM\"%w\".'||quote(name)FROM %s.sqlite_schema WHERE ty" ascii
        $s2 = ".?AV?$_Func_impl_no_alloc@V<lambda_1>@?2??pack_pkg_to_buffer@@YA_NAEBV?$basic_string@DU?$char_traits" ascii
        $s3 = ".?AV?$_Func_impl_no_alloc@V<lambda_1>@?2??run_vs_projects_scan@@YAXAEBV?$basic_string@DU?$char_trait" ascii
        $s4 = ".?AV<lambda_1>@?2??pack_pkg_to_buffer@@YA_NAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@" ascii
        $s5 = ".?AV<lambda_1>@?2??run_vs_projects_scan@@YAXAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D" ascii
        $s6 = ".?AV?$_Func_impl_no_alloc@P6A_NAEBV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z_N" ascii
        $s7 = ".?AV?$_Ref_count_obj2@$$CBUStubRuntimeDetail@@@std@@" ascii
        $s8 = "2@@std@@AEBUPkgMeta@@0AEBV?$unordered_map@V?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@s" ascii
        $s9 = ".?AV?$_Func_base@XAEAV?$basic_json@Vmap@std@@Vvector@2@V?$basic_string@DU?$char_traits@D@std@@V?$all" ascii
        $s10 = "@D@std@@V?$allocator@D@2@@std@@AEBUPkgMeta@@0AEBV?$unordered_map@V?$basic_string@DU?$char_traits@D@s" ascii
        $s11 = ".?AU?$output_adapter_protocol@D@detail@json_abi_v3_12_0@nlohmann@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 6652928 and 12 of them
}
