rule Sightlines_host_dda7b873_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-dda7b873"
        date = "2026-10-26"
        campaign = "host-dda7b873"
        family = "mirai"
        hash = "15c2b1e6708311802cd82e2383a752524ad7687368627a2b381ba652e42998bc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-dda7b873.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" ascii
        $s1 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s2 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s3 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s4 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s5 = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@ope" ascii
        $s6 = "group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256" ascii
        $s7 = "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" ascii
        $s8 = "203001010000 .mig.sh 2>/dev/null;   if [ -s .mig.sh ]; then sh .mig.sh 2>/dev/null; rm -f .mig.sh 2>" ascii
        $s9 = "/dev/null; break; fi; done; rm -f .mig.sh 2>/dev/null; rm -rf .k 2>/dev/null" ascii
        $s10 = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3" ascii
        $s11 = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@ope" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}
