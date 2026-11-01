rule Sightlines_tlsh_9de2707e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9de2707e"
        date = "2026-10-28"
        campaign = "tlsh-9de2707e"
        family = "mirai"
        hash = "0005299abc319e5180c5fc9609775583ecc8ca56ddc02153ff14c05b68736a47"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9de2707e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "kZPUbHYdNYRDXBjbR4SeWvUfvD5Sc90wMrC8XGa2Z54=" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s2 = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s" ascii
        $s3 = "Accept-Language: en-US,en;q=0.9" ascii
        $s4 = "X-Requested-With: XMLHttpRequest" ascii
        $s5 = "Accept-Encoding: gzip, deflate" ascii
        $s6 = "    -> skip TOCTOU: pid recycled" ascii
        $s7 = " skip=exe-owner-only(not-root)" ascii
        $s8 = "application/json,text/plain,*/*" ascii
        $s9 = "    -> skip TOCTOU: stat gone" ascii
        $s10 = "/sys/devices/system/cpu/online" ascii
        $s11 = "Content-Length: 2147483647" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
