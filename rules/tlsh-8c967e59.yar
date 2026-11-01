rule Sightlines_tlsh_8c967e59_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8c967e59"
        date = "2026-11-01"
        campaign = "tlsh-8c967e59"
        family = ""
        hash = "704a016be773737cd9612537ca7c287ea55b896d63d90785043a0728fe890886"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8c967e59.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xtern -mharden-sls=all -mrecord-mcount -mfentry -march=x86-64 -g -gdwarf-5 -O2 -std=gnu11 -p -fshort" ascii
        $s1 = "1 -falign-loops=1 -fno-asynchronous-unwind-tables -fno-jump-tables -fpatchable-function-entry=16,16 " ascii
        $s2 = "-call-used-regs=used-gpr -falign-functions=16 -fstrict-flex-arrays=3 -fno-strict-overflow -fstack-ch" ascii
        $s3 = "preferred-stack-boundary=3 -mskip-rax-setup -mtune=generic -mno-red-zone -mcmodel=kernel -mindirect-" ascii
        $s4 = "/usr/src/linux-headers-6.8.0-142-generic" ascii
        $s5 = "-wchar -funsigned-char -fno-common -fno-PIE -fno-strict-aliasing -fcf-protection=none -falign-jumps=" ascii
        $s6 = "__UNIQUE_ID___addressable_init_module342" ascii
        $s7 = "shift -fsanitize=bool -fsanitize=enum -fstack-protector-strong" ascii
        $s8 = "GNU C11 13.3.0 -mno-sse -mno-mmx -mno-sse2 -mno-3dnow -mno-avx -m64 -mno-80387 -mno-fp-ret-in-387 -m" ascii
        $s9 = "-pointer -fno-optimize-sibling-calls -ftrivial-auto-var-init=zero -fno-stack-clash-protection -fzero" ascii
        $s10 = "__UNIQUE_ID___addressable_cleanup_module343" ascii
        $s11 = "eck=no -fconserve-stack -fno-builtin-wcslen -fno-builtin-wcslen -fsanitize=bounds-strict -fsanitize=" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
