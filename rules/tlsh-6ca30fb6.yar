rule Sightlines_tlsh_6ca30fb6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6ca30fb6"
        date = "2026-10-31"
        campaign = "tlsh-6ca30fb6"
        family = ""
        hash = "04dc80d84f1452dc76e1962c10da1420a9d5ceb6e3a03691d274f98043ba74af"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6ca30fb6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "bad FPU precision (use D3DCREATE_FPU_PRESERVE with DirectX)" ascii
        $s1 = "unknown or malformed optimization flag '%s'" ascii
        $s2 = "PANIC: unprotected error in call to Lua API (" ascii
        $s3 = "ambiguous syntax (function call x new statement)" ascii
        $s4 = "<goto %s> jumps into the scope of local '%s'" ascii
        $s5 = "attempt to yield across C-call boundary" ascii
        $s6 = "NYI: cannot call this C function (yet)" ascii
        $s7 = "wrong number of arguments for function call" ascii
        $s8 = "runtime code generation failed, restricted kernel?" ascii
        $s9 = "attempt to perform arithmetic on '%s' and '%s'" ascii
        $s10 = "'setfenv' cannot change environment of given object" ascii
        $s11 = "'%s' expected (to close '%s' at line %d)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1134592 and 12 of them
}
