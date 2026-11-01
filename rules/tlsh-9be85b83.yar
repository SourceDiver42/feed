rule Sightlines_tlsh_9be85b83_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9be85b83"
        date = "2026-10-30"
        campaign = "tlsh-9be85b83"
        family = ""
        hash = "924ff15468634c7778e3f32de49ae6f7c5e412b2bb9d508fd577a1c9722a76fc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9be85b83.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "- No telemetry. Network requests (HTTPS only): ipwho.is / ipinfo.io (ISP and country), GitHub (Flows" ascii
        $s1 = "Contact: Telegram [@chepi1](https://t.me/chepi1), Discord `chepi228`." ascii
        $s2 = "van's [zapret2](https://github.com/bol-van/zapret2) (winws2) with all strategies of [Flowseal zapret" ascii
        $s3 = "-discord-youtube](https://github.com/Flowseal/zapret-discord-youtube) ported to zapret2. **The inter" ascii
        $s4 = "20 KB freeze on 36 hosting providers, Discord, YouTube, SoundCloud, 2K and EAC servers, and **harm**" ascii
        $s5 = "1. Download the archive from [Releases](https://github.com/chepi1/zapret/releases) and unpack it to " ascii
        $s6 = "[![tests](https://github.com/chepi1/zapret/actions/workflows/tests.yml/badge.svg)](https://github.co" ascii
        $s7 = "DPI bypass for **NBA 2K27**, **Discord** and **YouTube** on Windows, for Russian ISPs. Built on bol-" ascii
        $s8 = " bol-van (MIT), Flowseal strategies and lists (MIT), WinDivert and Cygwin (LGPL) " ascii
        $s9 = "4. Run `zapret.bat` (asks for admin rights), then: **5** " ascii
        $s10 = "3. Fully quit VPNs, proxy clients and game boosters." ascii
        $s11 = "2. Add the folder to your antivirus exclusions (`WinDivert64.sys` is a packet capture driver, often " ascii
    condition:
        filesize < 1048576 and 12 of them
}
