rule Sightlines_tlsh_665cdde3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-665cdde3"
        date = "2026-11-01"
        campaign = "tlsh-665cdde3"
        family = ""
        hash = "75f0dd780e7b28699c3dd6d37eae03d62d718e5e37463bda6975e4da4d31514d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-665cdde3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "# Required-Stop: $network $remote_fs $syslog" ascii
        $s1 = "# Required-Start: $network $remote_fs $syslog" ascii
        $s2 = "    echo \"Usage: $0 {start|stop|restart}\"" ascii
        $s3 = "# Short-Description: nyx-agent bot" ascii
        $s4 = "# Default-Start: 2 3 4 5" ascii
        $s5 = "# Provides: nyx-agent" ascii
        $s6 = "# Default-Stop: 0 1 6" ascii
        $s7 = "### BEGIN INIT INFO" ascii
        $s8 = "### END INIT INFO" ascii
        $s9 = "  restart)" ascii
        $s10 = "  start)" ascii
    condition:
        filesize < 1048576 and 11 of them
}
