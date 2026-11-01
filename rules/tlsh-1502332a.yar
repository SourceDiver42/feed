rule Sightlines_tlsh_1502332a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1502332a"
        date = "2026-10-28"
        campaign = "tlsh-1502332a"
        family = ""
        hash = "0f033a5a67ee7f6ea267e5677ca43b02accdf79e576db01ad13ef892346dfd3c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1502332a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "start \"zapret2: %~n0\" /min \"%BIN%winws2.exe\" --wf-tcp-out=80,443,2053,2083,2087,2096,8443,%GameFilte" ascii
        $s1 = "  --payload=discord_ip_discovery,stun --lua-desync=fake:blob=ACTIVE_DISCORD_UDP:repeats=6 --new ^" ascii
        $s2 = "  --payload=unknown --lua-desync=fake:blob=ACTIVE_GAME_UDP:repeats=12:payload=known,unknown" ascii
        $s3 = "--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --out-range=-d10 ^" ascii
        $s4 = "rTCP% --wf-udp-out=443,19294-19344,50000-50100,%GameFilterUDP% ^" ascii
        $s5 = "--blob=ACTIVE_GAME_UDP:@\"%BIN%ACTIVE_GAME_UDP.bin\" ^" ascii
        $s6 = "--blob=ACTIVE_DISCORD_UDP:@\"%BIN%ACTIVE_DISCORD_UDP.bin\" ^" ascii
        $s7 = "--filter-tcp=443 --hostlist=\"%LISTS%list-google.txt\" --out-range=-d10 ^" ascii
        $s8 = "--filter-tcp=80,443,8443 --ipset=\"%LISTS%ipset-all.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt\"" ascii
        $s9 = "--filter-tcp=80,443 --hostlist=\"%LISTS%list-general.txt\" --hostlist=\"%LISTS%list-general-user.txt\" -" ascii
        $s10 = "  --payload=quic_initial --lua-desync=fake:blob=quic_initial_www_google_com:repeats=6 --new ^" ascii
        $s11 = "  --payload=http_req --lua-desync=fake:blob=fake_default_http:repeats=6:tcp_ts=-600000 --new ^" ascii
    condition:
        filesize < 1048576 and 12 of them
}
