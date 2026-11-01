rule Sightlines_host_8d4aeae4_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-8d4aeae4"
        date = "2026-10-25"
        campaign = "host-8d4aeae4"
        family = "mirai"
        hash = "0d5e6bcebdb3b0e63d1274297ea60eb6aa3d67102cd06927f5c9fca1e56727be"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-8d4aeae4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "clang version 18.1.6 (https://github.com/ziglang/zig-bootstrap 98bc6bf4fc4009888d33941daf6b600d20a42" ascii
        $s1 = "systemctl enable %s.service 2>/dev/null" ascii
        $s2 = "    echo \"Usage: $0 {start|stop|restart}\"" ascii
        $s3 = "/usr/lib/accountsservice/accounts-daemon" ascii
        $s4 = "systemctl start %s.service 2>/dev/null" ascii
        $s5 = "REGISTER linux %s %d %ld %ld l4 %.0f %s" ascii
        $s6 = "update-rc.d %s defaults 2>/dev/null" ascii
        $s7 = "Description=System Update Service" ascii
        $s8 = "PATH=/usr/bin:/bin:/usr/local/bin" ascii
        $s9 = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3" ascii
        $s10 = "/usr/lib/systemd/systemd-timesyncd" ascii
        $s11 = "SSH-2.0-OpenSSH_9.2p1 Debian-2" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
