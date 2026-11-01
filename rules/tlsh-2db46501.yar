rule Sightlines_tlsh_2db46501_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2db46501"
        date = "2026-11-01"
        campaign = "tlsh-2db46501"
        family = "mirai"
        hash = "33df26a65740c720c1d8f5c74b1372089a73df6288cc75e198e89d68aa606826"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2db46501.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "[ -z \"$CAND\" ] && CAND=\"parm7 parm6 parm5 parm pmips pmpsl px86 pppc pm68k psh4\"" ascii
        $s1 = "cp /bin/busybox /tmp/ 2>/dev/null || cp /bin/busybox /var/tmp/ 2>/dev/null || cp /bin/busybox /var/r" ascii
        $s2 = "killall -9 x86_64 2>/dev/null; killall -9 x86_64.s 2>/dev/null" ascii
        $s3 = "/null || cp /bin/busybox /var/ 2>/dev/null || cp /bin/busybox /home/ 2>/dev/null || true" ascii
        $s4 = "/bin/busybox /mnt/ 2>/dev/null || cp /bin/busybox /root/ 2>/dev/null || cp /bin/busybox /opt/ 2>/dev" ascii
        $s5 = "killall -9 robben 2>/dev/null; killall -9 sora 2>/dev/null; killall -9 hajime 2>/dev/null" ascii
        $s6 = "un/ 2>/dev/null || cp /bin/busybox /run/ 2>/dev/null || cp /bin/busybox /dev/shm/ 2>/dev/null || cp " ascii
        $s7 = "killall -9 arm4 2>/dev/null; killall -9 arm4.s 2>/dev/null" ascii
        $s8 = "killall -9 arm5 2>/dev/null; killall -9 arm5.s 2>/dev/null" ascii
        $s9 = "killall -9 arm6 2>/dev/null; killall -9 arm6.s 2>/dev/null" ascii
        $s10 = "killall -9 arm7 2>/dev/null; killall -9 arm7.s 2>/dev/null" ascii
        $s11 = "killall -9 m68k 2>/dev/null; killall -9 m68k.s 2>/dev/null" ascii
    condition:
        filesize < 1048576 and 12 of them
}
