rule Sightlines_tlsh_0cb74316_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0cb74316"
        date = "2026-10-27"
        campaign = "tlsh-0cb74316"
        family = "mirai"
        hash = "351c9637fe7766c6fd4341e15853b5086631c5cf466f2166681ad867fcd0f49c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0cb74316.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/home/firmware/build/temp-sh4/gcc-core/gcc/config/sh/lib1funcs.asm" ascii
        $s1 = "__linuxthreads_initial_report_events" ascii
        $s2 = "__GI_pthread_attr_getschedpolicy" ascii
        $s3 = "__GI_pthread_attr_setschedpolicy" ascii
        $s4 = "__pthread_wait_for_restart_signal" ascii
        $s5 = "__stdio_mutex_initializer.3812" ascii
        $s6 = "__GI_pthread_attr_getinheritsched" ascii
        $s7 = "__GI___rpc_thread_svc_max_pollfd" ascii
        $s8 = "__GI_pthread_attr_setinheritsched" ascii
        $s9 = "__pthread_kill_other_threads_np" ascii
        $s10 = "__GI_pthread_attr_getschedparam" ascii
        $s11 = "__pthread_set_own_extricate_if" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
