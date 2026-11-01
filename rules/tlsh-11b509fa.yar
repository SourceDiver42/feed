rule Sightlines_tlsh_11b509fa_ladvix
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-11b509fa"
        date = "2026-11-01"
        campaign = "tlsh-11b509fa"
        family = "ladvix"
        hash = "01d5ce95105ec120abf4e9369b32040a01e93e0e5de533c4d5cdb9b52d50da82"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-11b509fa.json"
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
