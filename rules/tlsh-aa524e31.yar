rule Sightlines_tlsh_aa524e31_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-aa524e31"
        date = "2026-10-30"
        campaign = "tlsh-aa524e31"
        family = ""
        hash = "13b407513516565bb44d330e4f5018a6fdb8ccaac673a51a63f9a2ae42bcf009"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-aa524e31.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "FreeBSD clang version 10.0.0 (git@github.com:llvm/llvm-project.git llvmorg-10.0.0-0-gd32170dbd5b)" ascii
        $s1 = "$FreeBSD: releng/11.4/lib/csu/common/crtbrand.c 362094 2020-06-12 11:44:30Z gjb $" ascii
        $s2 = "$FreeBSD: releng/11.4/lib/csu/amd64/crt1.c 331722 2018-03-29 02:50:57Z eadler $" ascii
        $s3 = "$FreeBSD: releng/11.4/lib/csu/common/ignore_init.c 339300 2018-10-11 00:26:15Z emaste $" ascii
        $s4 = "$FreeBSD: releng/11.4/lib/csu/amd64/crtn.S 217105 2011-01-07 16:07:51Z kib $" ascii
        $s5 = "$FreeBSD: releng/11.4/lib/csu/amd64/crti.S 217105 2011-01-07 16:07:51Z kib $" ascii
        $s6 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s7 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s8 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s9 = "invalid parameter for prefix-length : %s" ascii
        $s10 = "invalid parameter for v4-threshold : %s" ascii
        $s11 = "invalid parameter for v6-threshold : %s" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
