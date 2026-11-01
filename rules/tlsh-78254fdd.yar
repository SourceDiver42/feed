rule Sightlines_tlsh_78254fdd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-78254fdd"
        date = "2026-10-30"
        campaign = "tlsh-78254fdd"
        family = ""
        hash = "0c55795717181156301fa4964b2637cd7b229feba5e36ef3ecb2d629da86dbbb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-78254fdd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "; override sockarg (SO_USER_COOKIE) for generated packets. default = 0x%08X (%u)" ascii
        $s1 = "FreeBSD clang version 10.0.0 (git@github.com:llvm/llvm-project.git llvmorg-10.0.0-0-gd32170dbd5b)" ascii
        $s2 = "$FreeBSD: releng/11.4/lib/csu/common/crtbrand.c 362094 2020-06-12 11:44:30Z gjb $" ascii
        $s3 = "$FreeBSD: releng/11.4/lib/csu/amd64/crt1.c 331722 2018-03-29 02:50:57Z eadler $" ascii
        $s4 = "$FreeBSD: releng/11.4/lib/csu/common/ignore_init.c 339300 2018-10-11 00:26:15Z emaste $" ascii
        $s5 = "; internal conntrack timeouts for TCP SYN, ESTABLISHED, FIN stages, UDP timeout. default %u:%u:%u:%u" ascii
        $s6 = "$FreeBSD: releng/11.4/lib/csu/amd64/crtn.S 217105 2011-01-07 16:07:51Z kib $" ascii
        $s7 = "$FreeBSD: releng/11.4/lib/csu/amd64/crti.S 217105 2011-01-07 16:07:51Z kib $" ascii
        $s8 = " --blob=<item_name>:[+ofs]@<filename>|0xHEX" ascii
        $s9 = "reconstructed packet due to VERDICT_MODIFY. size %zu => %zu" ascii
        $s10 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s11 = "aes_gcm: wrong key length %u. should be 16,24,32." ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1187680 and 12 of them
}
