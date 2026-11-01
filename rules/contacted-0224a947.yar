rule Sightlines_contacted_0224a947_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign contacted-0224a947"
        date = "2026-10-23"
        campaign = "contacted-0224a947"
        family = ""
        hash = "503225b031ced0ed5573439c14fcdc9116b4e0661f1b557b86f84d046f172803"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/contacted-0224a947.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "crosoft.com/SMI/2020/WindowsSettings\"><heapType>SegmentHeap</heapType></asmv3:windowsSettings></asmv" ascii
        $s1 = "3:application></assembly>" ascii
        $s2 = "invalid random_device value" ascii
        $s3 = "@SUVWAVHcA" ascii
        $s4 = "D$ H3L$ H3" ascii
        $s5 = "D$HL9wXt" ascii
        $s6 = "L$HH1D$ " ascii
        $s7 = "UVAUAVAWI" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 8 of them
}
