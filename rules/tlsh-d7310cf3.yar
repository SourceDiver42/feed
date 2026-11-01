rule Sightlines_tlsh_d7310cf3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d7310cf3"
        date = "2026-10-30"
        campaign = "tlsh-d7310cf3"
        family = ""
        hash = "58b2f17980b2812088e8cbd739c88e35969e22b13aad6e46e5952f539d5b83c7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d7310cf3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\"$NFQWS2\" --uid $WS_UID:$WS_GID --fwmark=$DESYNC_MARK --qnum=$QNUM --lua-init=@\"$ZAPRET_BASE/lua/zap" ascii
        $s1 = "echo $PKTWS or $MDIG is not available. run \\\"$ZAPRET_BASE/install_bin.sh\\\" or \\`make -C \\\"$ZAPRET_BA" ascii
        $s2 = "nft \"add rule inet $NFT_TABLE predefrag meta nfproto ipv${IPV} mark and $DESYNC_MARK !=0 notrack\"" ascii
        $s3 = "echo $PKTWS or $MDIG is not available. \\`gmake -C \\\"$ZAPRET_BASE\\\" bsd \\`" ascii
        $s4 = "IPT_ADD_DEL $1 INPUT $icmp_filter time-exceeded -m connmark --mark $DESYNC_MARK/$DESYNC_MARK $IPT_CO" ascii
        $s5 = "-H \"Content-Type: application/dns-message\" \"${3:-$DOH_SERVER}\" | \"$MDIG\" --dns-parse-query" ascii
        $s6 = "ZAPRET_CONFIG_DEFAULT=\"$ZAPRET_BASE/config.default\"" ascii
        $s7 = "\"$DVTWS2\" --port=$IPFW_DIVERT_PORT --lua-init=@\"$ZAPRET_BASE/lua/zapret-lib.lua\" --lua-init=@\"$ZAPRE" ascii
        $s8 = "DOH_SERVERS=${DOH_SERVERS:-\"https://cloudflare-dns.com/dns-query https://dns.google/dns-query https:" ascii
        $s9 = "for dom in $DNSCHECK_DOM; do echo $dom; done | \"$MDIG\" --threads=10 --family=4 >\"$DNSCHECK_DIGS\"" ascii
        $s10 = "curl_with_dig $1 \"$2\" $QUIC_PORT $HTTPS_HEAD -Ss -A \"$USER_AGENT\" --max-time $CURL_MAX_TIME_QUIC --h" ascii
        $s11 = "curl_probe $1 \"$2\" $HTTP_PORT \"$3\" -SsD \"$hdrt\" -A \"$USER_AGENT\" --max-time $CURL_MAX_TIME $CURL_OPT" ascii
    condition:
        filesize < 1048576 and 10 of them
}
