rule Sightlines_tlsh_563f36e7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-563f36e7"
        date = "2026-10-27"
        campaign = "tlsh-563f36e7"
        family = "mirai"
        hash = "00d0db4d3dbc46ce64f493b6d0df48a2c8e3b2c4c514a1f5159b8d2c8828cb8f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-563f36e7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s2 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "chacha20-poly1305@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@ope" ascii
        $s5 = "group-exchange-sha256,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256" ascii
        $s6 = "text/html, application/xhtml+xml, application/xml;q=0.9, */*;q=0.8" ascii
        $s7 = "SSH-2.0-OpenSSH_8.4p1 Debian-5+deb11u3" ascii
        $s8 = "umac-64-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@ope" ascii
        $s9 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6" ascii
        $s10 = "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,rsa-sha2-512,rsa-sha2-256" ascii
        $s11 = "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
