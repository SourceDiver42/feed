rule Sightlines_tlsh_90182bb0_gafgyt
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-90182bb0"
        date = "2026-10-28"
        campaign = "tlsh-90182bb0"
        family = "gafgyt"
        hash = "0a4ba0981607061511b773f6e4b029003d013aa5ea751148e8f7c44c1d2cd62c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-90182bb0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\K]6D3]4$T]^$DGD$DA3JO=*B4P&;7;1/proc/self/exe" ascii
        $s1 = "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" ascii
        $s2 = "\"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"" ascii
        $s3 = "Iranbot-Ultimate-V1 init: join t.me/flylegit" ascii
        $s4 = "upgrade-insecure-requests" ascii
        $s5 = "__vdso_clock_gettime64" ascii
        $s6 = "Connection: keep-alive" ascii
        $s7 = "sec-ch-ua-platform" ascii
        $s8 = "gzip, deflate, br" ascii
        $s9 = ".note.gnu.property" ascii
        $s10 = "/proc/self/status" ascii
        $s11 = "sec-ch-ua-mobile" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 11 of them
}
