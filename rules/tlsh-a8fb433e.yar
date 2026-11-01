rule Sightlines_tlsh_a8fb433e_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a8fb433e"
        date = "2026-11-01"
        campaign = "tlsh-a8fb433e"
        family = "mirai"
        hash = "03ff23bec6ef5c598dd1bbda72b789d0de03a3d6014fd3ba336d78cb6c4bc073"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a8fb433e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "mHoIJPqGRSTUVWXL\\s]Yrp|{nzt[D&'()*+,-./0123456789:;<=@A%$FuvwxyE}~l" ascii
        $s1 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s2 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s3 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s4 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s5 = "Content-Type: application/json" ascii
        $s6 = "/bin/busybox hostname PBOC" ascii
        $s7 = "GET /api/v1/status HTTP/1.1" ascii
        $s8 = "/bin/busybox wget http://" ascii
        $s9 = "POST /api/sync HTTP/1.1" ascii
        $s10 = "/bin/busybox echo -ne " ascii
        $s11 = "/bin/busybox echo > " ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 9 of them
}
