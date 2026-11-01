rule Sightlines_imphash_50a09960_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-50a09960"
        date = "2026-10-22"
        campaign = "imphash-50a09960"
        family = ""
        hash = "0be1298198e9ba2fa22ddcd6f1f0ef4f239d97ec0767e0ba083ae97bcc18945f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-50a09960.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "LuaJIT 2.1.0-beta3 -- Copyright (C) 2005-2017 Mike Pall. http://luajit.org/" ascii
        $s1 = "bad FPU precision (use D3DCREATE_FPU_PRESERVE with DirectX)" ascii
        $s2 = "JIT compiler disabled, CPU does not support SSE2" ascii
        $s3 = "  -O[opt]   Control LuaJIT optimizations." ascii
        $s4 = "unknown or malformed optimization flag '%s'" ascii
        $s5 = "unknown luaJIT command or jit.* modules not installed" ascii
        $s6 = "PANIC: unprotected error in call to Lua API (" ascii
        $s7 = "ambiguous syntax (function call x new statement)" ascii
        $s8 = "<goto %s> jumps into the scope of local '%s'" ascii
        $s9 = "attempt to yield across C-call boundary" ascii
        $s10 = "  -j cmd    Perform LuaJIT control command." ascii
        $s11 = "NYI: cannot call this C function (yet)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1756160 and 12 of them
}
