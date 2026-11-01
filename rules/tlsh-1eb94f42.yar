rule Sightlines_tlsh_1eb94f42_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1eb94f42"
        date = "2026-10-28"
        campaign = "tlsh-1eb94f42"
        family = ""
        hash = "58fa049941575e3f9918517d570a458dd0abc5fcc09a8b5745e0cf8615da932f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1eb94f42.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "::<Ka1@@AMc2\\\\]SRUOd3YYZVVY^^_ZZ]EX,<N(cF1001eegQQS,,-{{|xxyN9)OOP88:Qf5JJNR;*Q8&&6" ascii
        $s1 = "Ri5HHITk6JJKFFHQh4CCEUm7>>@AACLLMEEFbab_`aFZ.Pf3H\\0334667MMP<<=cceUUWJ^0\"0" ascii
        $s2 = "org/newsclub/net/unix/AFUNIXSocketChannel$$Lambda$1.classPK" ascii
        $s3 = "org/newsclub/net/unix/AFUNIXSocketChannel$$Lambda$2.classPK" ascii
        $s4 = "org/newsclub/net/unix/AFUNIXServerSocket$$Lambda$1.classPK" ascii
        $s5 = "org/newsclub/net/unix/AFUNIXServerSocket$$Lambda$2.classPK" ascii
        $s6 = "org/newsclub/net/unix/AFUNIXServerSocket$$Lambda$3.classPK" ascii
        $s7 = "org/newsclub/net/unix/AFUNIXServerSocket$$Lambda$4.classPK" ascii
        $s8 = "org/newsclub/net/unix/AFUNIXServerSocket$$Lambda$5.classPK" ascii
        $s9 = "org/newsclub/net/unix/AFUNIXServerSocket$$Lambda$6.classPK" ascii
        $s10 = "org/newsclub/net/unix/AFSYSTEMSocketAddress$1$$Lambda$2.classPK" ascii
        $s11 = "org/newsclub/net/unix/AFUNIXSelectorProvider$1$$Lambda$3.classPK" ascii
    condition:
        filesize < 11392318 and 12 of them
}
