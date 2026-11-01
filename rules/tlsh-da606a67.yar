rule Sightlines_tlsh_da606a67_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-da606a67"
        date = "2026-10-28"
        campaign = "tlsh-da606a67"
        family = ""
        hash = "021e15101f6ed2849d206a37d841fdd138a65938d17881e2defe9c415705b039"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-da606a67.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "start \"zapret2: %~n0\" /min \"%BIN%winws2.exe\" --wf-tcp-out=80,443,2053,2083,2087,2096,8443,%GameFilte" ascii
        $s1 = "  --payload=unknown --lua-desync=fake:blob=ACTIVE_GAME_UDP:repeats=10:payload=known,unknown" ascii
        $s2 = "--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --out-range=-d10 ^" ascii
        $s3 = "rTCP% --wf-udp-out=443,19294-19344,50000-50100,%GameFilterUDP% ^" ascii
        $s4 = "--blob=ACTIVE_GAME_UDP:@\"%BIN%ACTIVE_GAME_UDP.bin\" ^" ascii
        $s5 = "--blob=ACTIVE_DISCORD_UDP:@\"%BIN%ACTIVE_DISCORD_UDP.bin\" ^" ascii
        $s6 = "--filter-tcp=443 --hostlist=\"%LISTS%list-google.txt\" --out-range=-d10 ^" ascii
        $s7 = "--filter-tcp=80,443,8443 --ipset=\"%LISTS%ipset-all.txt\" --hostlist-exclude=\"%LISTS%list-exclude.txt\"" ascii
        $s8 = "  --payload=quic_initial --lua-desync=fake:blob=quic_initial_www_google_com:repeats=11 --new ^" ascii
        $s9 = "--filter-tcp=80,443 --hostlist=\"%LISTS%list-general.txt\" --hostlist=\"%LISTS%list-general-user.txt\" -" ascii
        $s10 = "--filter-udp=%GameFilterUDP% --ipset=\"%LISTS%ipset-all.txt\" --ipset-exclude=\"%LISTS%ipset-exclude.tx" ascii
        $s11 = "t-exclude=\"%LISTS%ipset-exclude-user.txt\" --out-range=-d10 ^" ascii
    condition:
        filesize < 1048576 and 10 of them
}
