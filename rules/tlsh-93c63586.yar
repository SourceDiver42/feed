rule Sightlines_tlsh_93c63586_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-93c63586"
        date = "2026-11-01"
        campaign = "tlsh-93c63586"
        family = "mirai"
        hash = "1ae26cf33fd6ad18aaae01ce8badf6d52782c9153167c37c2ec831723a314354"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-93c63586.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox chmod +x .d; ./.d; ./dvrHelper selfrep" ascii
        $s1 = " -r tftp.sh -l- | sh;/bin/busybox ftpget " ascii
        $s2 = "/wget.sh -O- | sh;/bin/busybox tftp -g " ascii
        $s3 = " ftpget.sh ftpget.sh && sh ftpget.sh;curl http://" ascii
        $s4 = "\"\\x2F\\x2A\\x3B\\x20\\x64\\x6F\\x0A\\x20\\x20\\x20\\x20\\x70\\x69\\x64\\x3D\\x24\\x7B\\x70\\x72\\x6F\\x63\\x5F\\x64\\x69\\x7" ascii
        $s5 = "\"\\x78\\x65\\x22\\x20\\x32\\x3E\\x20\\x2F\\x64\\x65\\x76\\x2F\\x6E\\x75\\x6C\\x6C\\x29\\x0A\\x0A\\x20\\x20\\x20\\x20\\x69\\x6" ascii
        $s6 = "\"\\x23\\x21\\x2F\\x62\\x69\\x6E\\x2F\\x73\\x68\\x0A\\x0A\\x66\\x6F\\x72\\x20\\x70\\x72\\x6F\\x63\\x5F\\x64\\x69\\x72\\x20\\x6" ascii
        $s7 = "\"\\x20\\x20\\x20\\x20\\x72\\x65\\x73\\x75\\x6C\\x74\\x3D\\x24\\x28\\x6C\\x73\\x20\\x2D\\x6C\\x20\\x22\\x2F\\x70\\x72\\x6F\\x6" ascii
        $s8 = "Content-Type: application/json" ascii
        $s9 = "/bin/busybox hostname PBOC" ascii
        $s10 = "GET /api/v1/status HTTP/1.1" ascii
        $s11 = "/bin/busybox wget http://" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 7 of them
}
