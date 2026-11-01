rule Sightlines_tlsh_7510d3a0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7510d3a0"
        date = "2026-10-30"
        campaign = "tlsh-7510d3a0"
        family = ""
        hash = "0ab0ed5f1fa6c1c40a28e26e87108018e178cff9d1e2355fc21040f8a976f47d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7510d3a0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d.googlesource.com/toolchain/llvm-project d8003a456d14a3deb8054cdaa529ffbf02d9b262)" ascii
        $s1 = "Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4 (https://androi" ascii
        $s2 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s3 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s4 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s5 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s6 = "could not read DNS reply blob from stdin" ascii
        $s7 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
        $s8 = "; log successfully resolved domains to a file" ascii
        $s9 = "could not write DNS query blob to stdout" ascii
        $s10 = "; print resolve stats to stderr every N domains" ascii
        $s11 = "eagain-delay must be within 0..100000" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
