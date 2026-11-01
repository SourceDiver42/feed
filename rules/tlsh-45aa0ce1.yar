rule Sightlines_tlsh_45aa0ce1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-45aa0ce1"
        date = "2026-10-28"
        campaign = "tlsh-45aa0ce1"
        family = ""
        hash = "01d48402275e46466877c2ae87ae260de693f378412c26042785b0f2f83f7a1b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-45aa0ce1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "start \"zapret2: %~n0\" /min \"%BIN%winws2.exe\" --wf-tcp-out=80,443,2053,2083,2087,2096,8443,%GameFilte" ascii
        $s1 = "  --payload=discord_ip_discovery,stun --lua-desync=fake:blob=ACTIVE_DISCORD_UDP:repeats=6 --new ^" ascii
        $s2 = "--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --out-range=-d10 ^" ascii
        $s3 = "rTCP% --wf-udp-out=443,19294-19344,50000-50100,%GameFilterUDP% ^" ascii
        $s4 = "--blob=ACTIVE_GAME_UDP:@\"%BIN%ACTIVE_GAME_UDP.bin\" ^" ascii
        $s5 = "--blob=ACTIVE_DISCORD_UDP:@\"%BIN%ACTIVE_DISCORD_UDP.bin\" ^" ascii
        $s6 = "--filter-tcp=443 --hostlist=\"%LISTS%list-google.txt\" --out-range=-d10 ^" ascii
        $s7 = "--filter-tcp=80,443,8443 --ipset=\"%LISTS%ipset-all.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt\"" ascii
        $s8 = "--filter-tcp=80,443 --hostlist=\"%LISTS%list-general.txt\" --hostlist=\"%LISTS%list-general-user.txt\" -" ascii
        $s9 = "  --payload=quic_initial --lua-desync=fake:blob=quic_initial_www_google_com:repeats=6 --new ^" ascii
        $s10 = "--filter-udp=%GameFilterUDP% --ipset=\"%LISTS%ipset-all.txt\" --ipset-exclude=\"%LISTS%ipset-exclude.tx" ascii
        $s11 = "t-exclude=\"%LISTS%ipset-exclude-user.txt\" --out-range=-d10 ^" ascii
    condition:
        filesize < 1048576 and 12 of them
}
