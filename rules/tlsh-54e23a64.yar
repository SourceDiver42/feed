rule Sightlines_tlsh_54e23a64_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-54e23a64"
        date = "2026-10-30"
        campaign = "tlsh-54e23a64"
        family = ""
        hash = "0254d77fb5b0561bc5a2e9a01cf47e8387f73adb9e18ff336867186c89cd660f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-54e23a64.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/usr/lib/libSystem.B.dylib" ascii
        $s1 = "_realpath$DARWIN_EXTSN" ascii
        $s2 = "__mh_execute_header" ascii
        $s3 = "___stack_chk_guard" ascii
        $s4 = "____chkstk_darwin" ascii
        $s5 = "___stack_chk_fail" ascii
        $s6 = "/tmp/log_de.log" ascii
        $s7 = "_gethostbyname" ascii
        $s8 = "/tmp/.X1-unix" ascii
        $s9 = "[kworker/0:2]" ascii
        $s10 = "/usr/lib/dyld" ascii
        $s11 = "__unwind_info" ascii
    condition:
        filesize < 1048576 and 12 of them
}
