rule Sightlines_tlsh_55d38a5e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-55d38a5e"
        date = "2026-10-15"
        campaign = "tlsh-55d38a5e"
        family = ""
        hash = "2dc4cd857195e02522a9a4c666c69c263517ded672775911241bdcb39af36b5a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-55d38a5e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "knownArmAmdGcnAarch64AsmjsAvrBpfebBpfelHexagonX86_32M68kLoongArch64Mips32Mips64Msp430Nvptx64Pulley32" ascii
        $s1 = "HelloExtensionWrongGroupForKeyShareUnsolicitedEchExtensionAES_128_GCMAES_256_GCMCHACHA20_POLY_1305EX" ascii
        $s2 = "SizeLimitExhaustedInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7" ascii
        $s3 = "StringLinkerNoteMetadataElfCompilationLinkageDynamicAarch64_Ilp32BpfCskyE2K32E2K64I386X86_64_X32Mips" ascii
        $s4 = "PskKeyExchangeModeHpkeSymmetricCipherSuitekdf_idaead_idWebPkiSupportedAlgorithms { all: [ .. ], mapp" ascii
        $s5 = "CritEdgeSSABBBranchEntryLiveinDisallowedBranchArgTooManyLiveRegsU6x0x1x2x3x4x5x6x7x8x9x10x11x12x13x1" ascii
        $s6 = "vmctxassertion failed: !(res.read_bit(BIT_LITTLE_ENDIAN) && res.read_bit(BIT_BIG_ENDIAN))" ascii
        $s7 = "assertion failed: max <= MAX_LOWERED_TYPES" ascii
        $s8 = "GenericX86SignedX86RipRelativeX86RipRelativeMovqX86BranchS390xDblAArch64CallLoongArchBranchSharcType" ascii
        $s9 = "rowSwitchI64Add128I64Sub128I64MulWideSI64MulWideUAcqRelSeqCstEngineModuleRecGroupModuleInternedTypeI" ascii
        $s10 = "iCudaCygwinDarwinDragonflyEmscriptenEspidfFreebsdFuchsiaHaikuHermitHorizonHurdIllumosIOSL4reLinuxMac" ascii
        $s11 = "assertion failed: len >= size_of::<c::sockaddr_in>()_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 11484160 and 12 of them
}
