rule Sightlines_tlsh_1e127db0_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1e127db0"
        date = "2026-10-28"
        campaign = "tlsh-1e127db0"
        family = "mirai"
        hash = "01911c7a254120e0a12cdd95d8ab4c1c0f71dcb6ae6e84ca55aec7940f7d94c3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1e127db0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s1 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s2 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s3 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s4 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s5 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s6 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s7 = "info[DT_RELENT]->d_un.d_val == sizeof (ElfW(Rel))" ascii
        $s8 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s9 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s10 = "chunksize_nomask (p) == (0 | PREV_INUSE)" ascii
        $s11 = "robust || (oldval & FUTEX_OWNER_DIED) == 0" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1734192 and 10 of them
}
