rule Sightlines_imphash_4f993e69_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4f993e69"
        date = "2026-10-17"
        campaign = "imphash-4f993e69"
        family = ""
        hash = "2ce6a4a50f9862f7338d077f9cefd90a02997c28add53588ad0e43c74bf750a7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4f993e69.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6d0da78}\"/><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/></application></compatibility><" ascii
        $s1 = "ortedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f" ascii
        $s2 = "_ZTVNSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_stri" ascii
        $s3 = "*NSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_stringI" ascii
        $s4 = "_ZNSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_string" ascii
        $s5 = "_ZTINSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_stri" ascii
        $s6 = "_ZTSNSt6thread11_State_implINS_8_InvokerISt5tupleIJZN7orchard11ripen_asyncERKNSt7__cxx1112basic_stri" ascii
        $s7 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{e20" ascii
        $s8 = "11457-1546-43c5-a5fe-008deee3d3f0}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supp" ascii
        $s9 = ".pdata$_ZNK12_GLOBAL__N_121system_error_category10equivalentEiRKSt15error_condition" ascii
        $s10 = ".xdata$_ZNK12_GLOBAL__N_121system_error_category10equivalentEiRKSt15error_condition" ascii
        $s11 = ".pdata.unlikely._ZNSt12_GLOBAL__N_1L14__throw_syserrEiPKc" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7660322 and 12 of them
}
