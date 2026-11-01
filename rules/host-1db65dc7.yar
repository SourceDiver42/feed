rule Sightlines_host_1db65dc7_mirai
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-1db65dc7"
        date = "2026-10-18"
        campaign = "host-1db65dc7"
        family = "mirai"
        hash = "006fe5e7d106546adda59d96a9509bc7ca21757c0b5d22c3f44565182652bba4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-1db65dc7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "/usr/local/bin/bash" ascii
        $s1 = "/usr/bin/busybox" ascii
        $s2 = "/data/local/tmp" ascii
        $s3 = "/tmp/.Kdat_tmp" ascii
        $s4 = "/usr/bin/bash" ascii
        $s5 = "/usr/bin/sh" ascii
        $s6 = ".comment" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 2114176 and 6 of them
}
