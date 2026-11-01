rule Sightlines_tlsh_25caa199_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-25caa199"
        date = "2026-10-21"
        campaign = "tlsh-25caa199"
        family = "mirai"
        hash = "6b34d756ff2a87f1a29d46176757f6c86f7ed890a0214b627d11e47420508848"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-25caa199.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8" ascii
        $s2 = "systemctl disable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s3 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8" ascii
        $s4 = "systemctl is-enabled systemd-network-helper.service >/dev/null 2>&1" ascii
        $s5 = "systemctl enable systemd-network-helper.service >/dev/null 2>&1" ascii
        $s6 = "nvram set rc_startup=\"%s\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s7 = "nvram set rc_startup=\"\" >/dev/null 2>&1 && nvram commit >/dev/null 2>&1" ascii
        $s8 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s9 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s.txt\"" ascii
        $s10 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
        $s11 = "systemctl daemon-reload >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
