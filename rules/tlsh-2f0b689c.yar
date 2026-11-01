rule Sightlines_tlsh_2f0b689c_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-2f0b689c"
        date = "2026-10-28"
        campaign = "tlsh-2f0b689c"
        family = "mirai"
        hash = "0f3c4dc91223d718577c8337ed7c03ef77097b992a78ffed87eea5f03e1bda78"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-2f0b689c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s1 = "/dev/FTWDT101_watchdog" ascii
        $s2 = "/dev/FTWDT101/watchdog" ascii
        $s3 = "/etc/default/watchdog" ascii
        $s4 = "/dev/misc/watchdog0" ascii
        $s5 = "/dev/misc/watchdog1" ascii
        $s6 = "/dev/misc/watchdog2" ascii
        $s7 = "/dev/earlywatchdog" ascii
        $s8 = "/dev/mbox/watchdog" ascii
        $s9 = "/dev/epdc/watchdog" ascii
        $s10 = "/dev/ssp/watchdog" ascii
        $s11 = "/dev/extwatchdog" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
