rule Sightlines_tlsh_4db15f8d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4db15f8d"
        date = "2026-10-30"
        campaign = "tlsh-4db15f8d"
        family = ""
        hash = "2b5786b17c516d9928f558ddbe44c21f75a573a3fced41f8456b70e5073f7e3e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4db15f8d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "   https://github.com/xxXdemidXxx/discord_obhod_app/releases/latest/download/ByPass-win-x64.zip" ascii
        $s1 = "https://github.com/xxXdemidXxx/discord_obhod_app/blob/main/USAGE.md" ascii
        $s2 = "https://github.com/xxXdemidXxx/discord_obhod_app/issues" ascii
        $s3 = "Telegram (experimental)" ascii
        $s4 = " ByPass-win-x64.zip:" ascii
        $s5 = " .NET Framework 4.8." ascii
        $s6 = " Telegram Desktop. " ascii
        $s7 = " Windows 10/11, 64 " ascii
        $s8 = " Google Secure DNS " ascii
        $s9 = " YouTube, ByPass " ascii
        $s10 = "DNS Windows, " ascii
        $s11 = " DNS Windows " ascii
    condition:
        filesize < 1048576 and 12 of them
}
