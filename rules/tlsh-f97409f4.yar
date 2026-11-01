rule Sightlines_tlsh_f97409f4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f97409f4"
        date = "2026-10-29"
        campaign = "tlsh-f97409f4"
        family = ""
        hash = "0034d4a18ee925ef19afa830e202918848aa2c4c150635332c1f32d0f27bbaa7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f97409f4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "set \"quicgoogle=\"%~dp0files\\quic_initial_www_google_com.bin\"\"" ascii
        $s1 = "set \"tlsgoogle=\"%~dp0files\\tls_clienthello_www_google_com.bin\"\"" ascii
        $s2 = "    set \"line=!line:{quicgoogle}=%quicgoogle%!\"" ascii
        $s3 = "    set \"line=!line:{youtube}=%youtube%!\"" ascii
        $s4 = "set \"youtube=\"%~dp0files\\youtube.txt\"\"" ascii
        $s5 = "    set \"line=!line:{tlsgoogle}=%tlsgoogle%!\"" ascii
        $s6 = "set \"ignore=\"%~dp0files\\ignore.txt\"\"" ascii
        $s7 = "set \"stun=\"%~dp0files\\stun.bin\"\"" ascii
        $s8 = "set \"pda=\"%~dp0files\\pda.bin\"\"" ascii
        $s9 = "setlocal enabledelayedexpansion" ascii
        $s10 = "chcp 65001 >nul" ascii
        $s11 = "set \"args=\"" ascii
    condition:
        filesize < 1048576 and 12 of them
}
