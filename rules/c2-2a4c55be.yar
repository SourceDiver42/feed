rule Sightlines_c2_2a4c55be_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign c2-2a4c55be"
        date = "2026-10-26"
        campaign = "c2-2a4c55be"
        family = "mirai"
        hash = "297aa3aff9848624c6b4b0b3411ade22f860671e84a8a1aaf2fb8983f968fb63"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/c2-2a4c55be.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s2 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s3 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s4 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s5 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s6 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s7 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s8 = "chunksize_nomask (p) == (0 | PREV_INUSE)" ascii
        $s9 = "robust || (oldval & FUTEX_OWNER_DIED) == 0" ascii
        $s10 = "lead_zero <= (base == 16 ? ((uintmax_t) exponent - (uintmax_t) INTMAX_MIN) / 4 : ((uintmax_t) expone" ascii
        $s11 = "e != EDEADLK || (kind != PTHREAD_MUTEX_ERRORCHECK_NP && kind != PTHREAD_MUTEX_RECURSIVE_NP)" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1849952 and 11 of them
}
