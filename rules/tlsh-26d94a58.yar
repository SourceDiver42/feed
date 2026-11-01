rule Sightlines_tlsh_26d94a58_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-26d94a58"
        date = "2026-10-28"
        campaign = "tlsh-26d94a58"
        family = "mirai"
        hash = "1db0ce93704bde6b3eb5c7aaaa95cfb6cd1883c737c801822a1f4fb923b58ad3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-26d94a58.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/dev/FTWDT101_watchdog" ascii
        $s1 = "/dev/FTWDT101/watchdog" ascii
        $s2 = "qVcVf(@Vg= Vhm#Vi}&Vj" ascii
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
