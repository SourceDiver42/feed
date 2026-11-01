rule Sightlines_tlsh_5b1a8a01_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5b1a8a01"
        date = "2026-10-27"
        campaign = "tlsh-5b1a8a01"
        family = "mirai"
        hash = "53bf22c4519282706701be4394ec3a289800944b8ae59c3afca7d22ae400eb62"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5b1a8a01.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" ascii
        $s1 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" ascii
        $s2 = "GCC: (GNU) 3.3.2 20031005 (Debian prerelease)" ascii
        $s3 = "__linuxthreads_initial_report_events" ascii
        $s4 = "__GI_pthread_attr_getschedpolicy" ascii
        $s5 = "__GI_pthread_attr_setschedpolicy" ascii
        $s6 = "__pthread_wait_for_restart_signal" ascii
        $s7 = "__GI_pthread_attr_getinheritsched" ascii
        $s8 = "__GI___rpc_thread_svc_max_pollfd" ascii
        $s9 = "__GI_pthread_attr_setinheritsched" ascii
        $s10 = "pthread_rwlockattr_setkind_np" ascii
        $s11 = "pthread_rwlockattr_getkind_np" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
