rule Sightlines_tlsh_9ae30148_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9ae30148"
        date = "2026-10-31"
        campaign = "tlsh-9ae30148"
        family = ""
        hash = "25e39a89addddcfb96273f38cf4e14c875af352e0942f8875c83bedc1e32a11c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9ae30148.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ".?AV?$_Func_impl_no_alloc@V<lambda_61b2317f6430986828c5b35896871436>@@XV?$shared_ptr@VClientHandlers" ascii
        $s1 = ".?AV?$_Func_impl_no_alloc@V<lambda_7d83b46dd0fcc695f3dff9759f1ae07a>@@PEAVRemoteQueryCallback@@H@std" ascii
        $s2 = ".?AV?$_Func_impl_no_alloc@V<lambda_b0ebd6983860228fff115410717f8a19>@@XV?$shared_ptr@VClientHandlers" ascii
        $s3 = ".?AV?$_Func_impl_no_alloc@V<lambda_09048d3a54f35910f3c676e261b15d6a>@@XV?$shared_ptr@VClientHandlers" ascii
        $s4 = ".?AV?$_Func_impl_no_alloc@V<lambda_006c2cff32bc3657877dbd6bab59e996>@@PEAVRemoteMessageRouter@@H@std" ascii
        $s5 = ".?AV?$_Func_impl_no_alloc@V<lambda_86aec3f2b56658c074fdaef7f1198610>@@XV?$shared_ptr@VClientHandlers" ascii
        $s6 = ".?AV?$_Func_impl_no_alloc@V<lambda_6f130847b96f25fd1f764f267224ab45>@@_NV?$shared_ptr@VClientHandler" ascii
        $s7 = ".?AV?$_Func_impl_no_alloc@V<lambda_4779a9f73928e4b1d19d65b06aea6c05>@@XV?$shared_ptr@VClientHandlers" ascii
        $s8 = ".?AV?$_Func_impl_no_alloc@V<lambda_46d7906b75a1c2c90fdf31e65516c09b>@@XV?$shared_ptr@VClientHandlers" ascii
        $s9 = ".?AV?$_Func_impl_no_alloc@V<lambda_78d3158004fee029a86853bb048411a0>@@XV?$shared_ptr@VClientHandlers" ascii
        $s10 = ".?AV?$_Func_impl_no_alloc@V<lambda_9969d70b162ac576d641a3c92c827bf7>@@XV?$shared_ptr@VClientHandlers" ascii
        $s11 = ".?AV?$_Func_impl_no_alloc@V<lambda_286c8b9f991e730d797e4548b77e10d4>@@_NV?$shared_ptr@VClientHandler" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3256320 and 12 of them
}
