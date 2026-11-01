rule Sightlines_tlsh_01cc20c0_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-01cc20c0"
        date = "2026-10-30"
        campaign = "tlsh-01cc20c0"
        family = "mirai"
        hash = "1442f715afabfbbb9c1ab2699832bd4f24c06b776ce0a04ccb5beedb067ffc20"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-01cc20c0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "851PGyBc7mdh4L72Viz5f9QggJuAzFTP9JXdvngQJFNh5nwRb8dpNjgWCDDC5T7JJ7HcKoAsRG1JWjkq5HqvcEBYHi1Yq8b" ascii
        $s1 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s2 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s3 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s4 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s5 = "((unsigned long) chunk2mem (brk) & MALLOC_ALIGN_MASK) == 0" ascii
        $s6 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s7 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s8 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s9 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s10 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s11 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1527500 and 12 of them
}
