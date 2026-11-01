rule Sightlines_tlsh_a63e7b96_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a63e7b96"
        date = "2026-10-28"
        campaign = "tlsh-a63e7b96"
        family = "mirai"
        hash = "075661075b4e05b4d770af74b7a21378c258e58c1925e08858c3fd4d9ee4de4b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a63e7b96.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/dev/FTWDT101_watchdog" ascii
        $s1 = "/dev/FTWDT101/watchdog" ascii
        $s2 = "/etc/default/watchdog" ascii
        $s3 = "/dev/misc/watchdog0" ascii
        $s4 = "/dev/misc/watchdog1" ascii
        $s5 = "/dev/misc/watchdog2" ascii
        $s6 = "/dev/earlywatchdog" ascii
        $s7 = "/dev/mbox/watchdog" ascii
        $s8 = "/dev/epdc/watchdog" ascii
        $s9 = "/dev/ssp/watchdog" ascii
        $s10 = "/dev/extwatchdog" ascii
        $s11 = "/dev/fw/watchdog" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
