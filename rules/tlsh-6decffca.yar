rule Sightlines_tlsh_6decffca_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6decffca"
        date = "2026-10-30"
        campaign = "tlsh-6decffca"
        family = ""
        hash = "297900940a70819388e29e775998accc477b3fd095e13bb0542d3b2d2783d64f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6decffca.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "FreeBSD clang version 10.0.0 (git@github.com:llvm/llvm-project.git llvmorg-10.0.0-0-gd32170dbd5b)" ascii
        $s1 = "$FreeBSD: releng/11.4/lib/csu/common/crtbrand.c 362094 2020-06-12 11:44:30Z gjb $" ascii
        $s2 = "$FreeBSD: releng/11.4/lib/csu/amd64/crt1.c 331722 2018-03-29 02:50:57Z eadler $" ascii
        $s3 = "$FreeBSD: releng/11.4/lib/csu/common/ignore_init.c 339300 2018-10-11 00:26:15Z emaste $" ascii
        $s4 = "$FreeBSD: releng/11.4/lib/csu/amd64/crtn.S 217105 2011-01-07 16:07:51Z kib $" ascii
        $s5 = "$FreeBSD: releng/11.4/lib/csu/amd64/crti.S 217105 2011-01-07 16:07:51Z kib $" ascii
        $s6 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s7 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s8 = "; time in msec to wait between EAI_AGAIN attempts. default %u" ascii
        $s9 = "; read from stdin binary DNS answer blob and parse it to ipv4/ipv6 addresses" ascii
        $s10 = "could not read DNS reply blob from stdin" ascii
        $s11 = "mdig stats : %02u:%02u:%02u : domains=%d success=%d error=%d" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
