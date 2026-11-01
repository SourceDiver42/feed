rule Sightlines_tlsh_fcd3df0e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fcd3df0e"
        date = "2026-10-28"
        campaign = "tlsh-fcd3df0e"
        family = ""
        hash = "01dae93af638e17f975ba53ed4f69b2983d96dab32e2a45b4280eb03bfbbccb1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fcd3df0e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s1 = "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"" ascii
        $s2 = ",:HVVVVVVdt-0X+0X 0X-0x+0x 0x" ascii
        $s3 = "upgrade-insecure-requests" ascii
        $s4 = "Connection: keep-alive" ascii
        $s5 = "__kernel_clock_gettime" ascii
        $s6 = "sec-ch-ua-platform" ascii
        $s7 = "gzip, deflate, br" ascii
        $s8 = "/proc/self/status" ascii
        $s9 = "sec-ch-ua-mobile" ascii
        $s10 = "GET %s HTTP/1.1" ascii
        $s11 = "en-US,en;q=0.9" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
