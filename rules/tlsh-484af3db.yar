rule Sightlines_tlsh_484af3db_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-484af3db"
        date = "2026-10-22"
        campaign = "tlsh-484af3db"
        family = ""
        hash = "0b24132bc1794daf323a3ce5ae8f5f14de7a161ab778fa89192514aa1b6966cf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-484af3db.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "function FindProxyForURL(url,host) {return \"DIRECT\";}" wide
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "WPADAuth value must be Anonymous, Basic, NTLM, or NTLMNoESS" wide
        $s3 = "DNSHost must be specified and fully qualified when using DNSTypes SOA or SRV" wide
        $s4 = "HTTPAuth value must be Anonymous, Basic, NTLM, or NTLMNoESS" wide
        $s5 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s6 = "ProxyAuth value must be Basic, NTLM, or NTLMNoESS" wide
        $s7 = " -WPADAuth                Default = NTLM: (Anonymous/Basic/NTLM/NTLMNoESS) HTTP/HTTPS listener authe" wide
        $s8 = " -MachineAccounts         Default = Disabled: (Y/N) Enable/Disable showing NTLM challenge/response c" wide
        $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s10 = "[-] Error starting unprivileged {1} listener, check IP and port usage." wide
        $s11 = " -HTTPAuth                Default = NTLM: (Anonymous/Basic/NTLM/NTLMNoESS) HTTP/HTTPS listener authe" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
