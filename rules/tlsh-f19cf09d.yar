rule Sightlines_tlsh_f19cf09d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f19cf09d"
        date = "2026-10-30"
        campaign = "tlsh-f19cf09d"
        family = ""
        hash = "1f3be370f80e835a608196f5c233d71c26d747aea73afaa6454d462bd35334a9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f19cf09d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "*DPI bypass for NBA 2K27, Discord and YouTube on Windows, built on bol-van's zapret2 with Flowseal's" ascii
        $s1 = " [zapret2](https://github.com/bol-van/zapret2) (winws2) " ascii
        $s2 = " [Flowseal zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube), " ascii
        $s3 = "- [zapret2](https://github.com/bol-van/zapret2) " ascii
        $s4 = "- [zapret-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) " ascii
        $s5 = "[![tests](https://github.com/chepi1/zapret/actions/workflows/tests.yml/badge.svg)](https://github.co" ascii
        $s6 = " WinDivert (Killer, Check Point, SmartByte, AdGuard), " ascii
        $s7 = " strategies. The interface is in Russian. English: [README.en.md](README.en.md).*" ascii
        $s8 = " [dpi-checkers](https://github.com/hyperion-cs/dpi-checkers), " ascii
        $s9 = "| `bin\\` | winws2.exe, WinDivert, cygwin1.dll " ascii
        $s10 = " [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)." ascii
        $s11 = " ALT Flowseal: fakedsplit, syndata, badseq, hostfakesplit " ascii
    condition:
        filesize < 1048576 and 12 of them
}
