rule Sightlines_tlsh_8e75bd6b_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8e75bd6b"
        date = "2026-10-30"
        campaign = "tlsh-8e75bd6b"
        family = "mirai"
        hash = "136a6f0521d66bf55c8b1bc7372559db4077665a05e372a1de918a1cb29f2cf0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8e75bd6b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "851PGyBc7mdh4L72Viz5f9QggJuAzFTP9JXdvngQJFNh5nwRb8dpNjgWCDDC5T7JJ7HcKoAsRG1JWjkq5HqvcEBYHi1Yq8b" ascii
        $s1 = "WARNING: Unsupported flag value(s) of 0x%x in DT_FLAGS_1." ascii
        $s2 = "WARNING: ld.so: invalid GLIBC_TUNABLES value `%.*s' for option `%s': ignored." ascii
        $s3 = "(_res_hconf.flags & HCONF_FLAG_MULTI) != 0" ascii
        $s4 = "ELFW(R_TYPE)(reloc->r_info) == ELF_MACHINE_JMP_SLOT" ascii
        $s5 = "info[DT_RELAENT]->d_un.d_val == sizeof (ElfW(Rela))" ascii
        $s6 = "WARNING: ld.so: invalid GLIBC_TUNABLES `%s': ignored." ascii
        $s7 = "info[DT_RELRENT]->d_un.d_val == sizeof (ElfW(Relr))" ascii
        $s8 = "version == NULL || !(flags & DL_LOOKUP_RETURN_NEWEST)" ascii
        $s9 = "(char *) chunk2mem (p) + 2 * CHUNK_HDR_SZ <= paligned_mem" ascii
        $s10 = "conf->nameserver_list[i]->sa_family == AF_INET6" ascii
        $s11 = " >/dev/null 2>&1 &\"].execute()}catch(Throwable t){}" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2253012 and 12 of them
}
