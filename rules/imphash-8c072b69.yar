rule Sightlines_imphash_8c072b69_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-8c072b69"
        date = "2026-10-30"
        campaign = "imphash-8c072b69"
        family = ""
        hash = "2b4a042dbe3d15182847f16e183fe1b504ff4f5c79d1b8cfd17777919beed52a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-8c072b69.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s1 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s2 = "; enable processing of empty tcp packets without flags SYN,RST,FIN (default : 0)" ascii
        $s3 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s4 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s5 = " tcp.PayloadLength>=12 and tcp.Payload32[0]==0x48545450 and tcp.Payload16[2]==0x2F31 and tcp.Payload" ascii
        $s6 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s7 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s8 = " deflate 1.3.1 Copyright 1995-2024 Jean-loup Gailly and Mark Adler " ascii
        $s9 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
        $s10 = "aes_ctr: wrong key length %u. should be 16,24,32." ascii
        $s11 = " inflate 1.3.1 Copyright 1995-2024 Mark Adler " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1312768 and 12 of them
}
