rule Sightlines_tlsh_f4224959_rustystealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-f4224959"
        date = "2026-11-01"
        campaign = "tlsh-f4224959"
        family = "rustystealer"
        hash = "0f666aca307f7fd2b974cfbff8da7054e71346d7368ee930049dcfea53edf5ef"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-f4224959.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "assertion failed: min_bits >= MIN_BITS/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rin" ascii
        $s1 = "called `Result::unwrap()` on an `Err` value/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557" ascii
        $s2 = "SizeLimitExhaustedParseIntErrorkindInvalidDigitPosOverflowNegOverflowZeroNotAPowerOfTwo/rustc/b94008" ascii
        $s3 = "assertion failed: len >= size_of::<c::sockaddr_in>()/rustc/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4/" ascii
        $s4 = "Cunsafe extern \"\" -fn( ->  + : punycode{}.llvm./rust/deps\\rustc-demangle-0.1.28\\src\\lib.rs" ascii
        $s5 = "Punycode overflows should not be possible due to PUNYCODE_ENCODE_MAX_INPUT_LENGTH" ascii
        $s6 = "assertion failed: value <= self.max_value()/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557" ascii
        $s7 = "CHUNK_SIZE_MAX_BYTES should fit any usize" ascii
        $s8 = "CertificateCompressionAlgorithmsecp256r1secp384r1secp521r1X25519X448CertificateTypeNamedGroupFFDHE20" ascii
        $s9 = "Proxy-Authorization: /root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/hyper-util-0.1.21/sr" ascii
        $s10 = "sample of invalid length/root/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/rustls-0.23.45/sr" ascii
        $s11 = "too many active read locks on RwLock/rustc/b940084d7eb6a299eb4bfeb8e34901bc051e7ac4/library\\std\\src\\" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4484096 and 12 of them
}
