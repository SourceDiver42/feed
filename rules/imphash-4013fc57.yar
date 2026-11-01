rule Sightlines_imphash_4013fc57_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4013fc57"
        date = "2026-10-22"
        campaign = "imphash-4013fc57"
        family = ""
        hash = "03a6e069a3af6c9905293868668280bac89d024e00c99e4313515a4f5f038401"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4013fc57.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "bad FPU precision (use D3DCREATE_FPU_PRESERVE with DirectX)" ascii
        $s1 = "JIT compiler disabled, CPU does not support SSE2" ascii
        $s2 = "unknown or malformed optimization flag '%s'" ascii
        $s3 = "PANIC: unprotected error in call to Lua API (" ascii
        $s4 = "Must use luaL_newstate() for 64 bit target" ascii
        $s5 = "ambiguous syntax (function call x new statement)" ascii
        $s6 = "<goto %s> jumps into the scope of local '%s'" ascii
        $s7 = "attempt to yield across C-call boundary" ascii
        $s8 = "NYI: cannot call this C function (yet)" ascii
        $s9 = "wrong number of arguments for function call" ascii
        $s10 = "runtime code generation failed, restricted kernel?" ascii
        $s11 = "attempt to perform arithmetic on '%s' and '%s'" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
