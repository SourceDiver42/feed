rule Sightlines_host_1f477a31_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-1f477a31"
        date = "2026-11-01"
        campaign = "host-1f477a31"
        family = ""
        hash = "197786c1b9008c2b87a5ae1db7d977a444bd4e658a95db1b92f0c594af637331"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-1f477a31.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "systemctl disable waternetwork.service 2>/dev/null" ascii
        $s1 = "systemctl enable waternetwork.service 2>/dev/null" ascii
        $s2 = "/etc/systemd/system/waternetwork.service" ascii
        $s3 = "systemctl daemon-reload 2>/dev/null" ascii
        $s4 = "Accept-Language: en-US,en;q=0.9" ascii
        $s5 = "Description=Water Network Service" ascii
        $s6 = "Accept-Encoding: gzip, deflate" ascii
        $s7 = "/etc/cron.d/waternetwork" ascii
        $s8 = "Cache-Control: no-cache" ascii
        $s9 = "Connection: keep-alive" ascii
        $s10 = "bile Safari/537.36" ascii
        $s11 = "After=network.target" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
