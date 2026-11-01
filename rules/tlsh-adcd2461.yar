rule Sightlines_tlsh_adcd2461_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-adcd2461"
        date = "2026-11-01"
        campaign = "tlsh-adcd2461"
        family = "mirai"
        hash = "01e5360067eb757682085ff66939c7190edbcab62cd00153b1e10ff6be9945e8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-adcd2461.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s1 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s2 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s3 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s4 = "\"\\x23\\x21\\x2F\\x62\\x69\\x6E\\x2F\\x73\\x68\\x0A\\x0A\\x66\\x6F\\x72\\x20\\x70\\x72\\x6F\\x63\\x5F\\x64\\x69\\x72\\x20\\x6" ascii
        $s5 = "Content-Type: application/json" ascii
        $s6 = "/bin/busybox hostname PBOC" ascii
        $s7 = "GET /api/v1/status HTTP/1.1" ascii
        $s8 = "/bin/busybox wget http://" ascii
        $s9 = "POST /api/sync HTTP/1.1" ascii
        $s10 = "/bin/busybox echo -ne " ascii
        $s11 = "/bin/busybox echo > " ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 5 of them
}
