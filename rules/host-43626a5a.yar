rule Sightlines_host_43626a5a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-43626a5a"
        date = "2026-10-29"
        campaign = "host-43626a5a"
        family = ""
        hash = "1c2972ea59fa21f1fb23e5ef294630d38f238e3edde70dd67a9ac0aef5bbee05"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-43626a5a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "history -c 2>/dev/null; rm -f ~/.bash_history 2>/dev/null" ascii
        $s1 = "x-svc|dropbear-agent|iptables-helper|sysd' 2>/dev/null" ascii
        $s2 = "pkill -9 -f 'kworker-helper|dhcpcd-monitor|ntpd-sync|udevd-helper|syslogd-rotate|crond-helper|netlin" ascii
        $s3 = "svc dropbear-agent iptables-helper sysd 2>/dev/null" ascii
        $s4 = "k-monitor|mdev-trigger|avahi-helper|dbus-monitor|logrotate-svc|tmpfiles-clean|resolved-helper|busybo" ascii
        $s5 = "monitor mdev-trigger avahi-helper dbus-monitor logrotate-svc tmpfiles-clean resolved-helper busybox-" ascii
        $s6 = "killall -9 kworker-helper dhcpcd-monitor ntpd-sync udevd-helper syslogd-rotate crond-helper netlink-" ascii
        $s7 = "    if command -v wget >/dev/null 2>&1; then" ascii
        $s8 = "    if command -v curl >/dev/null 2>&1; then" ascii
        $s9 = "    if command -v tftp >/dev/null 2>&1; then" ascii
        $s10 = "    for WD in /dev/watchdog /dev/watchdog0 /dev/misc/watchdog; do" ascii
        $s11 = "    rm -f /var/log/messages /var/log/syslog /var/log/auth.log /var/log/secure /var/log/wtmp 2>/dev/n" ascii
    condition:
        filesize < 1048576 and 12 of them
}
