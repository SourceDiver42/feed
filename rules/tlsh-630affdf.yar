rule Sightlines_tlsh_630affdf_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-630affdf"
        date = "2026-10-30"
        campaign = "tlsh-630affdf"
        family = ""
        hash = "24751f3bf2ba7bac3594d36c6e8e664f88c51dccd146017dd98d193035cf62cc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-630affdf.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s1 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s2 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s3 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s4 = "could not read DNS reply blob from stdin" ascii
        $s5 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
        $s6 = "; log successfully resolved domains to a file" ascii
        $s7 = "could not write DNS query blob to stdout" ascii
        $s8 = "; print resolve stats to stderr every N domains" ascii
        $s9 = "eagain-delay must be within 0..100000" ascii
        $s10 = "thread number must be within 1..100" ascii
        $s11 = "GCC: (crosstool-NG 1.28.0) 15.2.0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
