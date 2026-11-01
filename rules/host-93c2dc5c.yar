rule Sightlines_host_93c2dc5c_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-93c2dc5c"
        date = "2026-10-21"
        campaign = "host-93c2dc5c"
        family = "mirai"
        hash = "00b8c81a2b43524469dd3fa7a121e8c8701e7355ae5440bf108a54daac958fff"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-93c2dc5c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/var/tmp/%s\\nRestart=on-failure\\nRestartSec=30\\n[Install]\\nWantedBy=multi-user.target\\n' > /etc/syst" ascii
        $s1 = "printf '[Unit]\\nDescription=System Service\\nAfter=network.target\\n[Service]\\nType=simple\\nExecStart=" ascii
        $s2 = "echo '0' > /proc/sys/kernel/pid_max 2>/dev/null" ascii
        $s3 = "crontab -l 2>/dev/null | grep -v '%s' | crontab - 2>/dev/null" ascii
        $s4 = "find /tmp /var/tmp /dev/shm /root -name '*%s*' -delete 2>/dev/null" ascii
        $s5 = "chmod +x /var/tmp/%s /usr/lib/%s 2>/dev/null" ascii
        $s6 = "systemctl daemon-reload 2>/dev/null; systemctl enable %s 2>/dev/null" ascii
        $s7 = "rm -f /lib/systemd/system/%s.service 2>/dev/null" ascii
        $s8 = "systemctl stop %s 2>/dev/null; systemctl disable %s 2>/dev/null" ascii
        $s9 = "sed -i '/%s/d' /etc/rc.local 2>/dev/null" ascii
        $s10 = "rm -f /etc/systemd/system/%s.service 2>/dev/null" ascii
        $s11 = "chattr +i /var/tmp/%s 2>/dev/null" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
