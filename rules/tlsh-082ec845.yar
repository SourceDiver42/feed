rule Sightlines_tlsh_082ec845_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-082ec845"
        date = "2026-10-27"
        campaign = "tlsh-082ec845"
        family = "mirai"
        hash = "282307391902f2bab55be618ea6acf3d2c15871a45cd83b1b232558e8d31602e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-082ec845.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/bin/busybox iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" ascii
        $s1 = "/usr/bin/iptables -A INPUT -p tcp --dport 26721 -j ACCEPT" ascii
        $s2 = "__linuxthreads_pthread_sizeof_descr" ascii
        $s3 = "__linuxthreads_initial_report_events" ascii
        $s4 = "__linuxthreads_pthread_threads_max" ascii
        $s5 = "__GI_pthread_attr_getschedpolicy" ascii
        $s6 = "__GI_pthread_attr_setschedpolicy" ascii
        $s7 = "__pthread_wait_for_restart_signal" ascii
        $s8 = "__stdio_mutex_initializer.3862" ascii
        $s9 = "__GI_pthread_attr_getinheritsched" ascii
        $s10 = "__GI___rpc_thread_svc_max_pollfd" ascii
        $s11 = "__GI_pthread_attr_setinheritsched" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 10 of them
}
