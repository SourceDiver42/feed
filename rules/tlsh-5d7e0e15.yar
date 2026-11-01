rule Sightlines_tlsh_5d7e0e15_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-5d7e0e15"
        date = "2026-10-30"
        campaign = "tlsh-5d7e0e15"
        family = ""
        hash = "0defa131ec7e1d8ada99b9d04e4a20d7749711690b9d7cd696404595647c4671"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-5d7e0e15.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "kgo.com/\"https:/expand 32-byte kow.com/\"https://ation/xhtml+xml,A,en;q=0.9,fr-CA" ascii
        $s1 = "[+] compiled: gcc -O2 -static -DARCH=arm7 -DKILLER=1" ascii
        $s2 = "[+] mmap'd %s page-cache at %p (PROT_READ|MAP_SHARED)" ascii
        $s3 = "[0m BUG: byte changed but desired-value check mismatched index=%zu offset=%llu desired=%02x got=%02x" ascii
        $s4 = "[+] PRIMITIVE proven: root entry has empty passwd field via NSS." ascii
        $s5 = "[0m BUG: final verify mismatch index=%zu offset=%llu desired=%02x got=%02x" ascii
        $s6 = "[+] rxrpc module autoloaded via dummy socket(AF_RXRPC)" ascii
        $s7 = "q=0.8\"text/html,,application/xmlml+xml,applicatinge;v=b3;q=0.7\"tq=0.9,en;q=0.8\"j" ascii
        $s8 = "[*] /etc/passwd line 1 (root entry) BEFORE: '" ascii
        $s9 = "[+] uid/gid identity-mapped %u/%u; gained CAP_NET_RAW within netns" ascii
        $s10 = "le.com/\"https:///\"https://twittescord.com/\"httpson/xml;q=0.9,iman-US,en;q=0.9,es" ascii
        $s11 = "{\"id\":\"%s\",\"cmp\":\"%s\",\"stage\":\"beacon\",\"uptime\":%u,\"token\":\"eyJhbGciOiJIUzI1NiJ9.decoy.token\"}" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
