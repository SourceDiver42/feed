rule Sightlines_tlsh_75cd0115_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-75cd0115"
        date = "2026-10-31"
        campaign = "tlsh-75cd0115"
        family = ""
        hash = "2afac64b76f74e0312ece225edab6176e690ed0a9c0598c863008ffdee49b33b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-75cd0115.json"
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
