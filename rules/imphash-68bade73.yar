rule Sightlines_imphash_68bade73_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-68bade73"
        date = "2026-10-31"
        campaign = "imphash-68bade73"
        family = ""
        hash = "0749d8fc8e944d0576e1bb47120f87add8f875e5cd8968995633063fc79256f6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-68bade73.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "D:\\a\\_work\\1\\s\\src\\runtime\\artifacts\\obj\\coreclr\\windows.x64.Release\\jit\\clrjit.pdb" ascii
        $s1 = "NYI: Don't call genPopRegs with real regs!" ascii
        $s2 = "NYI: Don't call genPushRegs with real regs!" ascii
        $s3 = "JitGuardedDevirtualizationMaxTypeChecks" ascii
        $s4 = "ConvertToSByteWithTruncatedSaturationAndZeroExtendToInt32" ascii
        $s5 = "ConvertToByteWithTruncatedSaturationAndZeroExtendToInt32" ascii
        $s6 = "ConvertToSByteWithSaturationAndZeroExtendToInt32" ascii
        $s7 = "ConvertToByteWithSaturationAndZeroExtendToInt32" ascii
        $s8 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\jit\\codegenxarch.cpp" ascii
        $s9 = "CORINFO_HELP_GETDYNAMIC_NONGCTHREADSTATIC_BASE_NOCTOR_OPTIMIZED2" ascii
        $s10 = "D:\\a\\_work\\1\\s\\src\\runtime\\src\\coreclr\\jit\\codegencommon.cpp" ascii
        $s11 = "JitObjectStackAllocationBoxedValueClass" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4408848 and 12 of them
}
