rule Sightlines_tlsh_5b7aa1cb_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5b7aa1cb"
        date = "2026-10-26"
        campaign = "tlsh-5b7aa1cb"
        family = "mirai"
        hash = "0a2d1fe2f32d8c6f1adb5ffe9c767037c47870ffdff54373dfa7d6d0e9712cc6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5b7aa1cb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s1 = "mig.sh http://$H/bins/kla.sh 2>/dev/null ||    busybox wget -q -O .mig.sh http://$H/bins/kla.sh 2>/d" ascii
        $s2 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s4 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s5 = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@ope" ascii
        $s6 = "group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256" ascii
        $s7 = "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" ascii
        $s8 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s9 = "en sh .mig.sh 2>/dev/null; rm -f .mig.sh 2>/dev/null; break; fi; done; rm -f .mig.sh 2>/dev/null" ascii
        $s10 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/ieee754-df.S" ascii
        $s11 = "/home/landley/aboriginal/aboriginal/build/temp-armv7l/gcc-core/gcc/config/arm/lib1funcs.asm" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 3 of them
}
