rule Sightlines_tlsh_52bd91c5_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-52bd91c5"
        date = "2026-10-30"
        campaign = "tlsh-52bd91c5"
        family = "mirai"
        hash = "05f25a616835bbafe058502520d27d1978fb8766f1e95ff8567b97aea370288a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-52bd91c5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" ascii
        $s1 = "journalctl --rotate --vacuum-time=1s 2>/dev/null" ascii
        $s2 = "/etc/systemd/system/killer-helper.service" ascii
        $s3 = "__linuxthreads_initial_report_events" ascii
        $s4 = "Accept-Language: en-US,en;q=0.5" ascii
        $s5 = "__linuxthreads_pthread_threads_max" ascii
        $s6 = "Accept-Encoding: gzip, deflate" ascii
        $s7 = "__GI_pthread_attr_getschedpolicy" ascii
        $s8 = "__GI_pthread_attr_setschedpolicy" ascii
        $s9 = "0.0.0.0 www.hybrid-analysis.com" ascii
        $s10 = "__pthread_wait_for_restart_signal" ascii
        $s11 = "__GI_pthread_attr_getinheritsched" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 6 of them
}
