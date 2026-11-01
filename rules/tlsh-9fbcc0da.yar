rule Sightlines_tlsh_9fbcc0da_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9fbcc0da"
        date = "2026-10-30"
        campaign = "tlsh-9fbcc0da"
        family = ""
        hash = "035b00547dad583fb13d20f6cd3cc4e52ae3ede90595277293dd41f703efdd33"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9fbcc0da.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "d.googlesource.com/toolchain/llvm-project d8003a456d14a3deb8054cdaa529ffbf02d9b262)" ascii
        $s1 = "Android (13691557, +pgo, +bolt, +lto, +mlgo, based on r522817d) clang version 18.0.4 (https://androi" ascii
        $s2 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s3 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s4 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s5 = "invalid parameter for prefix-length : %s" ascii
        $s6 = "invalid parameter for v4-threshold : %s" ascii
        $s7 = "invalid parameter for v6-threshold : %s" ascii
        $s8 = " --prefix-length=min[-max]" ascii
        $s9 = " --v4-threshold=mul/div" ascii
        $s10 = "github version %s (%s)" ascii
        $s11 = "; ipv4 list (default)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
