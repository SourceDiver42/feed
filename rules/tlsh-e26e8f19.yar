rule Sightlines_tlsh_e26e8f19_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e26e8f19"
        date = "2026-10-28"
        campaign = "tlsh-e26e8f19"
        family = "mirai"
        hash = "1f715216367cfdb4e397d42e9fa665d783c182eaf2abc4f57310b04dd07ea846"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e26e8f19.json"
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
