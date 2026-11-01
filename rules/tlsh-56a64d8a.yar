rule Sightlines_tlsh_56a64d8a_ladvix
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-56a64d8a"
        date = "2026-10-30"
        campaign = "tlsh-56a64d8a"
        family = "ladvix"
        hash = "0062a03920d4a033a59c27f1d780dfd809781e57d3ff7b9585b062f3e4a53f76"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-56a64d8a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/lib64/ld-linux-x86-64.so.2" ascii
        $s1 = "_ITM_deregisterTMCloneTable" ascii
        $s2 = "_ITM_registerTMCloneTable" ascii
        $s3 = "Ym9uZ3JpcHo0amV6dXoK" ascii
        $s4 = "__libc_start_main" ascii
        $s5 = "__errno_location" ascii
        $s6 = "__stack_chk_fail" ascii
        $s7 = "__cxa_finalize" ascii
        $s8 = "__gmon_start__" ascii
        $s9 = "__strcpy_chk" ascii
        $s10 = "GLIBC_2.3.4" ascii
        $s11 = "__stpcpy_chk" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
