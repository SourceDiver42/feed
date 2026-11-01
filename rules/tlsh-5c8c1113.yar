rule Sightlines_tlsh_5c8c1113_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5c8c1113"
        date = "2026-11-01"
        campaign = "tlsh-5c8c1113"
        family = ""
        hash = "6b3e3afadbacc01515ba640d16e6dcab920fdf3b0fb764e1f335531637ad6463"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5c8c1113.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "TLS_HANDSHAKE_QUIC_TP_ADDRESS_DISCOVERY=0x9f81a176 -- https://tools.ietf.org/html/draft-ietf-quic-ad" ascii
        $s1 = "TLS_HANDSHAKE_QUIC_TP_CIBIR_ENCODING=0x1000 -- https://datatracker.ietf.org/doc/html/draft-banks-qui" ascii
        $s2 = "TLS_HANDSHAKE_QUIC_TP_ENABLE_TIME_STAMP_V2=0x7158 -- https://tools.ietf.org/html/draft-huitema-quic-" ascii
        $s3 = "TLS_HANDSHAKE_QUIC_TP_MIN_ACK_DELAY_OLD=0xde1a -- https://tools.ietf.org/html/draft-iyengar-quic-del" ascii
        $s4 = "TLS_HANDSHAKE_QUIC_TP_VERSION_INFORMATION=0x11 -- https://tools.ietf.org/html/draft-ietf-quic-versio" ascii
        $s5 = "TLS_HANDSHAKE_QUIC_TP_MIN_ACK_DELAY_DRAFT05=0xff04de1a -- https://tools.ietf.org/html/draft-ietf-qui" ascii
        $s6 = "TLS_HANDSHAKE_QUIC_TP_MIN_ACK_DELAY=0xff04de1b -- https://tools.ietf.org/html/draft-ietf-quic-ack-fr" ascii
        $s7 = "TLS_HANDSHAKE_QUIC_TP_LOSS_BITS=0x1057 -- https://tools.ietf.org/html/draft-ferrieuxhamchaoui-quic-l" ascii
        $s8 = "TLS_HANDSHAKE_QUIC_TP_MIN_ACK_DELAY_DRAFT_V1=0xFF03DE1A -- https://tools.ietf.org/html/draft-ietf-qu" ascii
        $s9 = "TLS_HANDSHAKE_QUIC_TP_VERSION_INFORMATION_DRAFT=0xff73db -- https://datatracker.ietf.org/doc/draft-i" ascii
        $s10 = "TLS_HANDSHAKE_QUIC_TP_ENABLE_TIME_STAMP=0x7157 -- https://tools.ietf.org/html/draft-huitema-quic-ts-" ascii
        $s11 = "TLS_HANDSHAKE_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE=0x20 -- https://datatracker.ietf.org/doc/html/draft-ie" ascii
    condition:
        filesize < 1048576 and 12 of them
}
