rule Sightlines_tlsh_5b2fd813_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5b2fd813"
        date = "2026-11-01"
        campaign = "tlsh-5b2fd813"
        family = ""
        hash = "23dc91f87469f5b7536fa073ab28bbb61c0234261d48f6dbbc664e81df1d94ce"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5b2fd813.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "authunix_create_default" ascii
        $s1 = "/lib/ld-linux.so.3" ascii
        $s2 = "__ctype_tolower_loc" ascii
        $s3 = "__ctype_toupper_loc" ascii
        $s4 = "__h_errno_location" ascii
        $s5 = "__libc_start_main" ascii
        $s6 = "clnt_pcreateerror" ascii
        $s7 = "fgets_unlocked" ascii
        $s8 = "__errno_location" ascii
        $s9 = "get_kernel_syms" ascii
        $s10 = "gethostbyname2" ascii
        $s11 = "gnu_dev_makedev" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
