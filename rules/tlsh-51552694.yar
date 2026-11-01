rule Sightlines_tlsh_51552694_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-51552694"
        date = "2026-10-30"
        campaign = "tlsh-51552694"
        family = ""
        hash = "3513e7f6dd838b5e4615592ce00b57f44a1f1ed95deb9c99d24b3998fed66754"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-51552694.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s1 = "GCC: (Realtek RSDK-4.6.4 Build 2002) 4.6.4" ascii
        $s2 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s3 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s4 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s5 = "could not read DNS reply blob from stdin" ascii
        $s6 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
        $s7 = "cannot create TLS data structures: ABORT" ascii
        $s8 = "; log successfully resolved domains to a file" ascii
        $s9 = "cannot allocate memory in static TLS block" ascii
        $s10 = "could not write DNS query blob to stdout" ascii
        $s11 = "; print resolve stats to stderr every N domains" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
