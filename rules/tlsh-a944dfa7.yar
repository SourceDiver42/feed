rule Sightlines_tlsh_a944dfa7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a944dfa7"
        date = "2026-11-01"
        campaign = "tlsh-a944dfa7"
        family = "mirai"
        hash = "05c458c702a87a6c4e49077aa19fe9b6c408ff2dd11468c1dc02868e29789100"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a944dfa7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s1 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s2 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s3 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s4 = "Content-Type: application/json" ascii
        $s5 = "/bin/busybox hostname PBOC" ascii
        $s6 = "GET /api/v1/status HTTP/1.1" ascii
        $s7 = "/bin/busybox wget http://" ascii
        $s8 = "POST /api/sync HTTP/1.1" ascii
        $s9 = "/bin/busybox echo -ne " ascii
        $s10 = "/bin/busybox echo > " ascii
        $s11 = "Host: api.svc.local" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 8 of them
}
