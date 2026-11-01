rule Sightlines_tlsh_11c8e538_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-11c8e538"
        date = "2026-10-21"
        campaign = "tlsh-11c8e538"
        family = "mirai"
        hash = "2e892431668abc0edfa63f56ec3558f8ab8db5ad57c2b27ccc2fe0a3273744f0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-11c8e538.json"
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
        $s10 = "%s: '%s' is not an ELF executable for MIPS" ascii
        $s11 = "mount -o remount,rw /system >/dev/null 2>&1" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1090464 and 12 of them
}
