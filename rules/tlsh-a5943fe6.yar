rule Sightlines_tlsh_a5943fe6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a5943fe6"
        date = "2026-10-30"
        campaign = "tlsh-a5943fe6"
        family = ""
        hash = "050084563e794755872cfe70b99a7654292674fbcf4a6dd11fdc7f2547af233c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a5943fe6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "?_LogWorkItemCompleted@_TaskEventLogger@details@Concurrency@@QEAAXXZ" ascii
        $s1 = "?_Makeushloc@_Locimp@locale@std@@CAXAEBV_Locinfo@3@HPEAV123@PEBV23@@Z" ascii
        $s2 = "?_LogTaskExecutionCompleted@_TaskEventLogger@details@Concurrency@@QEAAXXZ" ascii
        $s3 = "?_IsNonBlockingThread@_Task_impl_base@details@Concurrency@@SA_NXZ" ascii
        $s4 = "?_LogScheduleTask@_TaskEventLogger@details@Concurrency@@QEAAX_N@Z" ascii
        $s5 = "?_LogWorkItemStarted@_TaskEventLogger@details@Concurrency@@QEAAXXZ" ascii
        $s6 = "?_LogTaskCompleted@_TaskEventLogger@details@Concurrency@@QEAAXXZ" ascii
        $s7 = "aAbBcCdDeFgGhHIjmMnprRStTuUVwWxXyYzZ" ascii
        $s8 = "?_CallInContext@_ContextCallback@details@Concurrency@@QEBAXV?$function@$$A6AXXZ@std@@_N@Z" ascii
        $s9 = "?_Makewloc@_Locimp@locale@std@@CAXAEBV_Locinfo@3@HPEAV123@PEBV23@@Z" ascii
        $s10 = "?_Makexloc@_Locimp@locale@std@@CAXAEBV_Locinfo@3@HPEAV123@PEBV23@@Z" ascii
        $s11 = "?register_callback@ios_base@std@@QEAAXP6AXW4event@12@AEAV12@H@ZH@Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1171744 and 12 of them
}
