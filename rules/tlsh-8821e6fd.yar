rule Sightlines_tlsh_8821e6fd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8821e6fd"
        date = "2026-10-30"
        campaign = "tlsh-8821e6fd"
        family = ""
        hash = "070c1ba6ebba5185fc3ebe69c200b2fc2102cbfd52003e38dddfc8b340b707a4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8821e6fd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "start \"zapret2\" /min \"%~dp0bin\\winws2.exe\" \"--wf-tcp-out\" \"80,443,2053,2083,2087,2096,8443\" \"--wf-ud" ascii
        $s1 = "p-out\" \"443,19294-19344,50000-50100\" \"--lua-init=@%~dp0lua\\zapret-lib.lua\" \"--lua-init=@%~dp0lua\\zap" ascii
        $s2 = "tasklist /FI \"IMAGENAME eq winws.exe\" /NH 2>nul | findstr /I \"winws.exe\" >nul" ascii
        $s3 = "    echo ERROR: Zapret 1 is running - stop winws.exe first." ascii
        $s4 = "if not errorlevel 1 (" ascii
        $s5 = "@echo off" ascii
    condition:
        filesize < 1048576 and 5 of them
}
