rule Sightlines_tlsh_9f0a2f12_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9f0a2f12"
        date = "2026-10-30"
        campaign = "tlsh-9f0a2f12"
        family = ""
        hash = "286a0cfa1b98f66f96ca83b33669317b4627eec2e5d4ad119191b8263144897a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9f0a2f12.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "_google:@%~dp0blobs\\quic_initial_www_google_com.bin\" \"--lua-gc\" \"60\" \"--filter-udp\" \"19294-19344,500" ascii
        $s1 = "a-desync=fake:blob=quic_google\" \"--new\" \"--filter-tcp\" \"2053,2083,2087,2096,8443\" \"--filter-l7\" \"tls" ascii
        $s2 = "start \"zapret2\" /min \"%~dp0bin\\winws2.exe\" \"--wf-tcp-out\" \"80,443,2053,2083,2087,2096,8443\" \"--wf-ud" ascii
        $s3 = "p-out\" \"443,19294-19344,50000-50100\" \"--lua-init=@%~dp0lua\\zapret-lib.lua\" \"--lua-init=@%~dp0lua\\zap" ascii
        $s4 = "tasklist /FI \"IMAGENAME eq winws.exe\" /NH 2>nul | findstr /I \"winws.exe\" >nul" ascii
        $s5 = "ret-antidpi.lua\" \"--blob\" \"google_tls:@%~dp0blobs\\tls_clienthello_www_google_com.bin\" \"--blob\" \"quic" ascii
        $s6 = "00-50100\" \"--filter-l7\" \"discord,stun\" \"--payload\" \"discord_ip_discovery\" \"--out-range\" \"-d10\" \"--lu" ascii
        $s7 = "    echo ERROR: Zapret 1 is running - stop winws.exe first." ascii
        $s8 = "if not errorlevel 1 (" ascii
        $s9 = "@echo off" ascii
    condition:
        filesize < 1048576 and 10 of them
}
