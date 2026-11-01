rule Sightlines_tlsh_a59464ec_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a59464ec"
        date = "2026-10-23"
        campaign = "tlsh-a59464ec"
        family = "mirai"
        hash = "10a76ea06517991202d6766a1d55e5aba67e81600f67ea55bcbf5363ac1f6d42"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a59464ec.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "curl -s -o /dev/null --max-time 15 -w '%{speed_download} %{size_download}' 'https://speed.cloudflare" ascii
        $s1 = "PRIVMSG %s :KILLED bot=%s sig=%d killer_pid=%d killer_uid=%d comm=%s exe=%s" ascii
        $s2 = "[%s] speedtest: %.2f Mbps down (%.2f MB/s, %.1f MB sample) [curl]" ascii
        $s3 = "[%s] arch: pointer=%d-bit, endian=%s, caps: threads=%d discord_socks=%d" ascii
        $s4 = "[%s] start_flood: usage: <mode> <ip> <port> [args]" ascii
        $s5 = ".com/__down?bytes=10000000' 2>/dev/null" ascii
        $s6 = "command -v speedtest-cli >/dev/null 2>&1" ascii
        $s7 = "[%s] pps_onepacket size=%d socks=%d %ds" ascii
        $s8 = "[%s] killall t%d %s syns=%ld ok=%ld writes=%ld" ascii
        $s9 = "4 32 33 36 35 65 64 66 72 34 35 34 77 72 71 65 4E 65 24 ED 65 76 E8 E7 98 7E AE D9 8E 79 87 AE AE 8E" ascii
        $s10 = "/var/tmp/.systemd-resolved-helper" ascii
        $s11 = "4 34 32 33 36 35 65 64 66 72 34 35 34 77 72 71 65 4E 65 24 ED 65 76 E8 E7 98 7E AE D9 8E 79 87 AE AE" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
