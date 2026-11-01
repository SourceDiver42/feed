rule Sightlines_imphash_795eb4ac_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-795eb4ac"
        date = "2026-10-27"
        campaign = "imphash-795eb4ac"
        family = ""
        hash = "2548b7c1bda26e55dca101f8cfc781dbc6b5dba7eb7f3fafc5f968d468570502"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-795eb4ac.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "CHUNK_SIZE_MAX_BYTES should fit any usizeC:\\Users\\it\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5" ascii
        $s1 = "invalid WINDOW_UPDATE frameC:\\Users\\it\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\h2-0.4.1" ascii
        $s2 = "ed: size <= proto::MAX_WINDOW_SIZEC:\\Users\\it\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\h" ascii
        $s3 = "RUST_BACKTRACE\\...lock count overflow in reentrant mutex/rustc/8bab26f4f68e0e26f0bb7960be334d5b520ea" ascii
        $s4 = "invalid RST_STREAM frameC:\\Users\\it\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\h2-0.4.15\\s" ascii
        $s5 = "size overflows MAX_SIZEC:\\Users\\it\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\http-1.4.2\\s" ascii
        $s6 = "b9mspwefOV2NSHH8+NzBZbhnddgeYCJRnQtPZpQMHUg= " ascii
        $s7 = "invalid GOAWAY frameC:\\Users\\it\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\h2-0.4.15\\src\\p" ascii
        $s8 = "StreamIdConnTask Future polled twiceC:\\Users\\it\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f" ascii
        $s9 = "Previous URL must be validC:\\Users\\it\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\reqwest-0" ascii
        $s10 = "\" -fn() ->  + : punycode{}.llvm./rust/deps\\rustc-demangle-0.1.27\\src\\lib.rs" ascii
        $s11 = "Errassertion failed: buf.len() <= u32::MAX as usize/rustc/8bab26f4f68e0e26f0bb7960be334d5b520ea452/l" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5844144 and 12 of them
}
