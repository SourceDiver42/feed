rule Sightlines_tlsh_f2cc54d3_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f2cc54d3"
        date = "2026-10-31"
        campaign = "tlsh-f2cc54d3"
        family = ""
        hash = "1f546f1b4b2cd404fdd2ba9b52223ecf935ad26588993f703bef69db4c94034e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f2cc54d3.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "LuaJIT 2.1.0-beta3 -- Copyright (C) 2005-2017 Mike Pall. http://luajit.org/" ascii
        $s1 = "  -O[opt]   Control LuaJIT optimizations." ascii
        $s2 = "unknown luaJIT command or jit.* modules not installed" ascii
        $s3 = "  -j cmd    Perform LuaJIT control command." ascii
        $s4 = "  -i        Enter interactive mode after executing 'script'." ascii
        $s5 = "  -         Execute stdin and stop handling options." ascii
        $s6 = "  -E        Ignore environment variables." ascii
        $s7 = "cannot create state: not enough memory" ascii
        $s8 = "  -e chunk  Execute string 'chunk'." ascii
        $s9 = "  -v        Show version information." ascii
        $s10 = "  -l name   Require library 'name'." ascii
        $s11 = "(error object is not a string)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 11 of them
}
