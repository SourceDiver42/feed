rule Sightlines_imphash_24df5360_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-24df5360"
        date = "2026-10-31"
        campaign = "imphash-24df5360"
        family = ""
        hash = "0109e6b251ab56b80f6c02a51a92f03f44a9b1ad410f2cf3cf6b7dd6543139a9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-24df5360.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Yhttp://www.microsoft.com/pkiops/crl/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crl0w" ascii
        $s1 = "[http://www.microsoft.com/pkiops/certs/Microsoft%20Windows%20Code%20Signing%20PCA%202024.crt0" ascii
        $s2 = "CSW::GFW - managed exception handling code frame (%p)" ascii
        $s3 = "D:\\a\\_work\\1\\s\\src\\runtime\\artifacts\\obj\\coreclr\\windows.x64.Release\\dlls\\mscordbi\\mscordbi.pdb" ascii
        $s4 = "'Microsoft Windows Code Signing PCA 20240" ascii
        $s5 = "4-D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\debug\\di\\rstype.cpp" ascii
        $s6 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\debug\\di\\divalue.cpp" ascii
        $s7 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\debug\\di\\hash.cpp" ascii
        $s8 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\debug\\di\\rsthread.cpp" ascii
        $s9 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\debug\\di\\rsmain.cpp" ascii
        $s10 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\debug\\di\\rsregsetcommon.cpp" ascii
        $s11 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\debug\\di\\process.cpp" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2475776 and 12 of them
}
