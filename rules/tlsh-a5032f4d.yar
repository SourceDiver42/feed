rule Sightlines_tlsh_a5032f4d_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a5032f4d"
        date = "2026-11-01"
        campaign = "tlsh-a5032f4d"
        family = "mirai"
        hash = "204e6d14591590ac52bc5c342ceb5ca87abdaa90d29b6e7cd1c84ebc291e7c5a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a5032f4d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/proc/self/oom_score_adj" ascii
        $s1 = "/etc/config/resolv.conf" ascii
        $s2 = "After=network.target" ascii
        $s3 = "/usr/bin/systemctl" ascii
        $s4 = "/etc/config/hosts" ascii
        $s5 = "Restart=always" ascii
        $s6 = "[kworker/0:1]" ascii
        $s7 = "ExecStart=%s" ascii
        $s8 = "/etc/rc.local" ascii
        $s9 = "[Service]" ascii
        $s10 = "E8H;E0wrH" ascii
        $s11 = "tcpbypass" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 6 of them
}
