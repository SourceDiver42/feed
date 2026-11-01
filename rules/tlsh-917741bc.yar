rule Sightlines_tlsh_917741bc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-917741bc"
        date = "2026-10-30"
        campaign = "tlsh-917741bc"
        family = ""
        hash = "44f8fcef8a604b2dc35820a20a174f93306c90489512db4d53a865f2199e6f20"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-917741bc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "`BATCH=1 DOMAINS=bbc.com CURL_CMD=1 SKIP_DNSCHECK=1 /opt/zapret2/blockcheck2.sh`" ascii
        $s1 = "local idx_sni = array_field_search(tdis.handshake[TLS_HANDSHAKE_TYPE_CLIENT].dis.ext, \"type\", TLS_EX" ascii
        $s2 = "table.insert(tdis.handshake[TLS_HANDSHAKE_TYPE_CLIENT].dis.ext, 1, { type = TLS_EXT_SERVER_NAME, dis" ascii
        $s3 = "Replaces the `<HOSTLIST>` and `<HOSTLIST_NOAUTO>` markers in $1 depending on the [MODE_FILTER](#conf" ascii
        $s4 = "_UNREACH_ADDR<br>ICMP6_DST_UNREACH_NOPORT | number | icmpv6 code for destination unreachable | ipv6 " ascii
        $s5 = "- Checks based on [DESYNC_FWMARK](#config-file)." ascii
        $s6 = "  <summary><b>Example of parsing `https://user:pass@domain.com:12345/my_uri/script.php?a=1&b=3`</b><" ascii
        $s7 = "nft add rule inet ztest pre iifname $IFACE_WAN udp sport \"{$PORTS_UDP}\" ct reply packets 1-$MAX_PKT_" ascii
        $s8 = "- Checking by [DESYNC_FWMARK](#config-file)." ascii
        $s9 = "table.insert(tdis.handshake[TLS_HANDSHAKE_TYPE_CLIENT].dis.ext[idx_sni].dis.list, { name = \"example." ascii
        $s10 = "(Google), AS16509 (Amazon), AS16276 (OVH), AS24940 (Hetzner). Whitelisted ASNs: AS47541 (VK), AS3523" ascii
        $s11 = "You can locally override [config](#config-file) variables and apply `FW_EXTRA_POST` and `FW_EXTRA_PR" ascii
    condition:
        filesize < 1048576 and 12 of them
}
