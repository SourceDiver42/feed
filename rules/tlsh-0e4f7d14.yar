rule Sightlines_tlsh_0e4f7d14_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-0e4f7d14"
        date = "2026-10-15"
        campaign = "tlsh-0e4f7d14"
        family = ""
        hash = "0234f3afddedb16450e7f9c51ec55a3c935ce568806a7c1888aae048d44ae441"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-0e4f7d14.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ParseIntErrorEmptyInvalidDigitPosOverflowNegOverflowZero_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7" ascii
        $s1 = "i32i64f32f64StackOverflowMemoryOutOfBoundsHeapMisalignedTableOutOfBoundsIndirectCallToNullBadSignatu" ascii
        $s2 = "<assemblyIdentity version=\"1.0.0.0\" name=\"mozglue\" type=\"win32\"/>" ascii
        $s3 = "assertion failed: code < MAX_HUFF_SYMBOLS_2" ascii
        $s4 = "LazyLock instance has previously been poisoned_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/______" ascii
        $s5 = "eCalling Web API crypto.getRandomValues failedrandSecure: VxWorks RNG module is not initializedNode." ascii
        $s6 = "RandomCopyBytes: iOS Security framework failureRtlGenRandom: Windows system function failureRDRAND: " ascii
        $s7 = "assertion failed: self.is_char_boundary(new_len)_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/____" ascii
        $s8 = "a Display implementation returned an error unexpectedly_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f" ascii
        $s9 = "js crypto CommonJS module is unavailableCalling Node.js API crypto.randomFillSync failedNode.js ES m" ascii
        $s10 = "Utf8Errorvalid_up_toerror_lenNoneSomeAccessError_______ac68faa20c58cbccd01ee7208bf3b6e93a7d7f96/____" ascii
        $s11 = "?InvalidArrayIndex_CRASH@detail@mozilla@@YAX_K0@Z" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1309696 and 12 of them
}
