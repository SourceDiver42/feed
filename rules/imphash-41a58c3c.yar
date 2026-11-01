rule Sightlines_imphash_41a58c3c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-41a58c3c"
        date = "2026-10-31"
        campaign = "imphash-41a58c3c"
        family = ""
        hash = "4e2109c88298f0a614aac82b23310b13835673a8e192a6a8b75c25459e591169"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-41a58c3c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Yhttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crl0w" ascii
        $s1 = "[http://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "D:\\a\\_work\\1\\s\\src\\runtime\\artifacts\\obj\\coreclr\\windows.x64.Release\\dlls\\mscordac\\mscordaccore.pdb" ascii
        $s3 = "'Microsoft Windows Code Signing PCA 20240" ascii
        $s4 = "System.Threading.Thread.UseAllCpuGroups" wide
        $s5 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\vm\\typehandle.cpp" ascii
        $s6 = "CORINFO_HELP_GETDYNAMIC_NONGCTHREADSTATIC_BASE_NOCTOR_OPTIMIZED2" ascii
        $s7 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\vm\\method.cpp" ascii
        $s8 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\vm\\threads.cpp" ascii
        $s9 = "CORINFO_HELP_GETDYNAMIC_GCTHREADSTATIC_BASE_NOCTOR_OPTIMIZED" ascii
        $s10 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\debug\\daccess\\enummem.cpp" ascii
        $s11 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\vm\\peimage.cpp" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2713280 and 12 of them
}
