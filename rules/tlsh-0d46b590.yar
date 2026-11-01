rule Sightlines_tlsh_0d46b590_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0d46b590"
        date = "2026-10-29"
        campaign = "tlsh-0d46b590"
        family = "mirai"
        hash = "24a31a0910c04b88dd28b7c421e9ba311f86adcd7d18437318e9c2ac790da116"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0d46b590.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "USER-AGENT: Google Chrome/60.0.3112.90 Windows" ascii
        $s1 = "%s():%i: Trying to dlopen '%s', RTLD_GLOBAL:%d RTLD_NOW:%d" ascii
        $s2 = "%s: '%s' is not an ELF executable for ARCompact" ascii
        $s3 = "%s():%i: Circular dependency, skipping '%s'," ascii
        $s4 = "%s():%i: Beginning dlopen relocation fixups" ascii
        $s5 = "%s():%i: Move %s from pos %d to %d in INIT/FINI list." ascii
        $s6 = "ST: urn:dial-multiscreen-org:service:dial:1" ascii
        $s7 = "%s:%i: RELRO protecting %s:  start:%x, end:%x" ascii
        $s8 = "%s():%i: running ctors for library %s at '%p'" ascii
        $s9 = "%s():%i: running dtors for library %s at '%p'" ascii
        $s10 = "cannot create TLS data structures: ABORT" ascii
        $s11 = "%s: cannot apply additional memory protection after relocation" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
