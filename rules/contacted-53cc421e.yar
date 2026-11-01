rule Sightlines_contacted_53cc421e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-53cc421e"
        date = "2026-11-01"
        campaign = "contacted-53cc421e"
        family = "mirai"
        hash = "bd412af2559841d5738563fc903900c50c01c80a473f6a0e96bdc02fa6484fcb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-53cc421e.json"
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
        $s8 = "expand 32-byte kexpand 16-byte kSECP256R1" ascii
        $s9 = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s10 = "Content-Disposition: form-data; name=\"file\"; filename=\"%s.txt\"" ascii
        $s11 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1081536 and 12 of them
}
