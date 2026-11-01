rule Sightlines_tlsh_5c7707f1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5c7707f1"
        date = "2026-10-31"
        campaign = "tlsh-5c7707f1"
        family = ""
        hash = "23a8050ec68542989b6da6cc906a90faf8a14e6416fd2871a260b781b1c374ae"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5c7707f1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Reserving %zd bytes (%.3f mb) for GC bookkeeping failed" ascii
        $s1 = "ParseGCHeapAffinitizeRange failed, check your HeapAffinitizeRanges config" ascii
        $s2 = "This process is affinitize to 0 CPUs, check your GC heap affinity related configs" ascii
        $s3 = "compute_hard_limit failed, check your heap hard limit related configs" ascii
        $s4 = "Committing %zd bytes for a region failed" ascii
        $s5 = "System.GC.UOHWaitBGCSizeIncPercent" ascii
        $s6 = "System.GC.DGen0GrowthMaxFactor" ascii
        $s7 = "System.GC.DGen0GrowthMinFactor" ascii
        $s8 = "System.GC.DGen0GrowthPercent" ascii
        $s9 = "System.GC.Gen0MaxBudget" ascii
        $s10 = "System.GC.LOHThreshold" ascii
        $s11 = "GCCacheSizeFromSysConf" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1422928 and 12 of them
}
