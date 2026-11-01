rule Sightlines_tlsh_7cad1b00_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-7cad1b00"
        date = "2026-10-27"
        campaign = "tlsh-7cad1b00"
        family = "mirai"
        hash = "0be273779ab4cc6cebd141822b211480e1769bc8bb3b66e8b9c94a2b511687d2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-7cad1b00.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "__linuxthreads_initial_report_events" ascii
        $s1 = "__GI_pthread_attr_getschedpolicy" ascii
        $s2 = "__GI_pthread_attr_setschedpolicy" ascii
        $s3 = "__pthread_wait_for_restart_signal" ascii
        $s4 = "__GI_pthread_attr_getinheritsched" ascii
        $s5 = "__GI___rpc_thread_svc_max_pollfd" ascii
        $s6 = "__stdio_mutex_initializer.3828" ascii
        $s7 = "__GI_pthread_attr_setinheritsched" ascii
        $s8 = "pthread_cond_timedwait_relative" ascii
        $s9 = "__pthread_kill_other_threads_np" ascii
        $s10 = "__GI_pthread_attr_getschedparam" ascii
        $s11 = "__pthread_set_own_extricate_if" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
