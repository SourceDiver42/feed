rule Sightlines_tlsh_1cb5eb26_amos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1cb5eb26"
        date = "2026-10-16"
        campaign = "tlsh-1cb5eb26"
        family = "amos"
        hash = "57a671a61a6fbebe17b09d9baa5712d3b0af8232fd807697183c6b1fb67286a4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1cb5eb26.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation" ascii
        $s1 = "/System/Library/Frameworks/Security.framework/Versions/A/Security" ascii
        $s2 = "/usr/lib/libSystem.B.dylib" ascii
        $s3 = "/usr/lib/libc++.1.dylib" ascii
        $s4 = "@___stack_chk_guard" ascii
        $s5 = "@dyld_stub_binder" ascii
        $s6 = "@_mach_task_self_" ascii
        $s7 = "@___stack_chk_fail" ascii
        $s8 = "@_pthread_once" ascii
        $s9 = "__la_symbol_ptr" ascii
        $s10 = "__mod_init_func" ascii
        $s11 = "@___clear_cache" ascii
    condition:
        filesize < 2661984 and 12 of them
}
