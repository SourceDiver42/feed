rule Sightlines_imphash_dd85b31b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-dd85b31b"
        date = "2026-10-30"
        campaign = "imphash-dd85b31b"
        family = ""
        hash = "2c08e77f86b0953cffa505bdbe64e87ecb7c088db65d5acb9a2eee65a32565ef"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-dd85b31b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "(Press Retry to debug the application - JIT must be enabled)" ascii
        $s1 = "failure, see the Visual C++ documentation on asserts" ascii
        $s2 = "api-ms-win-core-kernel32-legacy-l1-1-1.dll" ascii
        $s3 = "api-ms-win-core-processthreads-l1-1-0.dll" ascii
        $s4 = "api-ms-win-core-processenvironment-l1-1-0.dll" ascii
        $s5 = "api-ms-win-core-errorhandling-l1-1-0.dll" ascii
        $s6 = "api-ms-win-core-processthreads-l1-1-1.dll" ascii
        $s7 = "api-ms-win-core-libraryloader-l1-1-0.dll" ascii
        $s8 = "Assertion failed: %Ts, file %Ts, line %d" ascii
        $s9 = "api-ms-win-core-localization-l1-2-0.dll" ascii
        $s10 = "For information on how your program can cause an assertion" ascii
        $s11 = "api-ms-win-core-interlocked-l1-1-0.dll" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2746656 and 12 of them
}
