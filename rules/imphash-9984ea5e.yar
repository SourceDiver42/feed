rule Sightlines_imphash_9984ea5e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9984ea5e"
        date = "2026-11-01"
        campaign = "imphash-9984ea5e"
        family = ""
        hash = "3e64a72d9226a356193b15889065e505ec2a3ced63948d01989c1f5e167aa4fb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-9984ea5e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/Create/F/TNMicrosoftEdgeUpdate/TR/SCONLOGONSoftware\\Classes\\CLSID\\{BCDE0395-E52F-467C-8E3D-C4579291" ascii
        $s1 = "RUST_BACKTRACEassertion failed: self.is_code_point_boundary(new_len)/rustc/58cf8f9c35b355199727627d0" ascii
        $s2 = "Software\\Classes\\CLSID\\{AB8902B4-09CA-4bb6-B78D-A8F59079A7D2}WindowsWebCache" ascii
        $s3 = "692E}\\InprocServer32Software\\Classes\\CLSID\\{AB8902B4-09CA-4bb6-B78D-A8F59079A7D2}\\InprocServer32" ascii
        $s4 = "MMDevApi.dllDllGetClassObjectC:\\Users\\hermes\\.cargo\\registry\\src\\index.crates.io-1949cf8c6b5b557f\\un" ascii
        $s5 = "overflow in Duration::new/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\core\\src\\time.rs" ascii
        $s6 = "SizeLimitExhaustedErrorParseIntErrorkind/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\core" ascii
        $s7 = "assertion failed: self.is_char_boundary(new_len)/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/libr" ascii
        $s8 = "<unknown>/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\std\\src\\sys\\process\\windows\\child_p" ascii
        $s9 = "Cunsafe extern \"\" -fn() ->  + : punycode{}.llvm./rust/deps\\rustc-demangle-0.1.28\\src\\lib.rs" ascii
        $s10 = "too many active read locks on RwLock/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\std\\src\\" ascii
        $s11 = "advancing IoSlice beyond its length/rustc/58cf8f9c35b355199727627d07ae34a4e2846d67/library\\core\\src\\" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
