rule Sightlines_tlsh_6f1864ec_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6f1864ec"
        date = "2026-10-28"
        campaign = "tlsh-6f1864ec"
        family = ""
        hash = "0d0a21cd2129901ddcedebe2c5f5a4245d589ba605dd523cbc880775607c5d68"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6f1864ec.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "start \"zapret2\" /min \"%~dp0bin\\winws2.exe\" \"--wf-tcp-out\" \"80,443,2053,2083,2087,2096,8443\" \"--wf-tc" ascii
        $s1 = "tasklist /FI \"IMAGENAME eq winws.exe\" /NH 2>nul | findstr /I \"winws.exe\" >nul" ascii
        $s2 = "    echo ERROR: Zapret 1 is running - stop winws.exe first." ascii
        $s3 = "if not errorlevel 1 (" ascii
        $s4 = "@echo off" ascii
    condition:
        filesize < 1048576 and 5 of them
}
