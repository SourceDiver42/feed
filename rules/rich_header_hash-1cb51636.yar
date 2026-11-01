rule Sightlines_rich_header_hash_1cb51636_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-1cb51636"
        date = "2026-11-01"
        campaign = "rich_header_hash-1cb51636"
        family = ""
        hash = "56ea849523ffc5f31539a60cc97a7272c344bec9feea9cff11a847be97fe4633"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-1cb51636.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "stuvwxyz0123456789+,!\"#$%&'()*+,-0123456789@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdehijklmpqrC:\\Users\\runnera" ascii
        $s1 = "LISTEN_FAKETLS_DOMAINDC_IPTarget IP for a DC, e.g. `--dc-ip 2:149.154.167.220`. Can be specified mul" ascii
        $s2 = "s.buf-kb256TG_BUF_KBPOOL_SIZENumber of pre-warmed WebSocket connections per DCpool-size4TG_POOL_SIZE" ascii
        $s3 = "S zone.cf-worker-domaincfproxy-worker-domainTG_CF_WORKER_DOMAINCF_PRIORITYLegacy: try the Cloudflare" ascii
        $s4 = "RUST_BACKTRACEassertion failed: self.is_code_point_boundary(new_len)/rustc/58cf8f9c35b355199727627d0" ascii
        $s5 = "o the same hole.  Matches upstream tg-ws-proxy's `IP_FAIL_COOLDOWN`.ip-fail-cooldown3600TG_IP_FAIL_C" ascii
        $s6 = "OXY`, then `HTTP_PROXY` (including lowercase variants).outbound-proxyURLTG_OUTBOUND_PROXYNO_OUTBOUND" ascii
        $s7 = "ed exits non-zero, because nothing was verified.check-listenerTG_CHECK_LISTENERDEFAULT_DOMAINSUse th" ascii
        $s8 = ". `host1:443:sec1,host2:8888:sec2`mtproto-proxyHOST:PORT:SECRETTG_MTPROTO_PROXYLINK_IPIP address to " ascii
        $s9 = " MTProto proxy after a failureupstream-fail-cooldown60TG_UPSTREAM_FAIL_COOLDOWNCF_CONNECT_TIMEOUTCon" ascii
        $s10 = " the default priority order (see docs/Fallbacks.md).pinned-upstreamTIERSTG_PINNED_UPSTREAMPINNED_MED" ascii
        $s11 = "CHUNK_SIZE_MAX_BYTES should fit any usizeC:\\Users\\runneradmin\\.cargo\\registry\\src\\index.crates.io-19" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 17315840 and 12 of them
}
