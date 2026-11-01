rule Sightlines_tlsh_b9d340c4_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b9d340c4"
        date = "2026-11-01"
        campaign = "tlsh-b9d340c4"
        family = ""
        hash = "0888ee97db33d39719fcae5493adddd48c06cf483e5fb5f70ed342227eb314f2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b9d340c4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s1 = "((tcp.Ack and tcp.Syn or tcp.Rst or tcp.Fin) or (tcp.PayloadLength>=12 and tcp.Payload32[0]==0x48545" ascii
        $s2 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s3 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s4 = "WARNING !!! possible TRASH FLOOD configuration detected in profile %d" ascii
        $s5 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s6 = " --filter-l7=[http|tls|quic|wireguard|dht|discord|stun|unknown] ; L6-L7 protocol filter. multiple co" ascii
        $s7 = " inflate 1.3.1 Copyright 1995-2024 Mark Adler " ascii
        $s8 = "; perform TCP split handshake : send SYN only, SYN+ACK or ACK+SYN" ascii
        $s9 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkCards" ascii
        $s10 = "seqovl>=split_pos (%zu>=%zu). cancelling seqovl for part %d." ascii
        $s11 = "WARNING !!! in most cases this is acceptable only with custom payload based windivert filter (--wf-r" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}
