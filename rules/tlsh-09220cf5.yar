rule Sightlines_tlsh_09220cf5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-09220cf5"
        date = "2026-11-01"
        campaign = "tlsh-09220cf5"
        family = ""
        hash = "027ee20166749752ec93c0cd25d25744f6496e969d0f43c75373a6d2ffd0c84f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-09220cf5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s2 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s3 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s4 = "http://mkhkjxgchtfgu7uhofxzgoawntfzrkdccymveektqgpxrpjb72oq.b32.i2p/cgi-bin/prometei.cgi" ascii
        $s5 = "%s: Symbol `%s' causes overflow in R_X86_64_PC32 relocation" ascii
        $s6 = "_dl_debug_initialize (0, args.nsid)->r_state == RT_CONSISTENT" ascii
        $s7 = "_dl_debug_initialize (0, args->nsid)->r_state == RT_CONSISTENT" ascii
        $s8 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s9 = "ELFW(R_TYPE) (reloc->r_info) == R_X86_64_RELATIVE" ascii
        $s10 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
        $s11 = "lead_zero <= (base == 16 ? (uintmax_t) INTMAX_MAX / 4 : (uintmax_t) INTMAX_MAX)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2577750 and 11 of them
}
