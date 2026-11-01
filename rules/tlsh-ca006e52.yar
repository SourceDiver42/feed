rule Sightlines_tlsh_ca006e52_ladvix
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ca006e52"
        date = "2026-11-01"
        campaign = "tlsh-ca006e52"
        family = "ladvix"
        hash = "1a00edbe089690d8592264a94d3be8daf3391395d7798879b66eb6dea611a566"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ca006e52.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<>@o$:,.l+*^?=)(|AB&%;D{!wkUxzvutsrqp_nm-ihgfFCcba~K23456789eyd1XSNQWTZMIRHGVOYLjPJE/][" ascii
        $s1 = "program_invocation_short_name" ascii
        $s2 = "obstack_alloc_failed_handler" ascii
        $s3 = "/lib64/ld-linux-x86-64.so.2" ascii
        $s4 = "_ITM_deregisterTMCloneTable" ascii
        $s5 = "_ITM_registerTMCloneTable" ascii
        $s6 = "Ym9uZ3JpcHo0amV6dXoK" ascii
        $s7 = "program_invocation_name" ascii
        $s8 = "__ctype_get_mb_cur_max" ascii
        $s9 = "_obstack_memory_used" ascii
        $s10 = "_obstack_allocated_p" ascii
        $s11 = "__isoc23_strtoumax" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
