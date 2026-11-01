rule Sightlines_tlsh_f4d4c610_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f4d4c610"
        date = "2026-10-22"
        campaign = "tlsh-f4d4c610"
        family = ""
        hash = "0141e546ec16e5a2d0aac816932506aca117c3c59c7cc4d933441e1f92267079"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f4d4c610.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "bad FPU precision (use D3DCREATE_FPU_PRESERVE with DirectX)" ascii
        $s1 = "  -O[opt]   Control LuaJIT optimizations." ascii
        $s2 = "unknown or malformed optimization flag '%s'" ascii
        $s3 = "unknown luaJIT command or jit.* modules not installed" ascii
        $s4 = "PANIC: unprotected error in call to Lua API (" ascii
        $s5 = "ambiguous syntax (function call x new statement)" ascii
        $s6 = "<goto %s> jumps into the scope of local '%s'" ascii
        $s7 = "attempt to yield across C-call boundary" ascii
        $s8 = "  -j cmd    Perform LuaJIT control command." ascii
        $s9 = "NYI: cannot call this C function (yet)" ascii
        $s10 = "wrong number of arguments for function call" ascii
        $s11 = "runtime code generation failed, restricted kernel?" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1520640 and 12 of them
}
