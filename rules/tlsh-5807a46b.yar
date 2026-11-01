rule Sightlines_tlsh_5807a46b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5807a46b"
        date = "2026-10-23"
        campaign = "tlsh-5807a46b"
        family = ""
        hash = "83c3dd36cc47df184e97ae167bf09cdb173ad3b5022fd6e3b81da50b640e2001"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5807a46b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/usr/lib/arm-linux-gnueabihf/crt1.o" ascii
        $s1 = "/usr/lib/arm-linux-gnueabihf/crtn.o" ascii
        $s2 = "/usr/lib/arm-linux-gnueabihf/crti.o" ascii
        $s3 = "__do_global_dtors_aux_fini_array_entry" ascii
        $s4 = "__libc_start_main@@GLIBC_2.4" ascii
        $s5 = "gethostbyname@@GLIBC_2.4" ascii
        $s6 = "_ITM_deregisterTMCloneTable" ascii
        $s7 = "__frame_dummy_init_array_entry" ascii
        $s8 = "/lib/ld-linux-armhf.so.3" ascii
        $s9 = "_ITM_registerTMCloneTable" ascii
        $s10 = "setsockopt@@GLIBC_2.4" ascii
        $s11 = "inet_addr@@GLIBC_2.4" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
