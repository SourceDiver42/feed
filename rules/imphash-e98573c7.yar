rule Sightlines_imphash_e98573c7_netsupport
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e98573c7"
        date = "2026-10-22"
        campaign = "imphash-e98573c7"
        family = "netsupport"
        hash = "3f9cdacaf03050325aa554e4f7bc769ce2fe9554a06237a1ec8a191bade0bf18"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e98573c7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Usage: %s (4 InheritableEventHandles) (CommandLineToSpawn)" ascii
        $s1 = "@Microsoft Visual C++ Runtime Library" wide
        $s2 = "NetSupport Remote Command Prompt" wide
        $s3 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPAD" ascii
        $s4 = "DDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDIN" ascii
        $s5 = "@4@5D5H5L5P5T5X5\\5`5d5h5l5p5t5x5|5" ascii
        $s6 = "557;7A7G7M7S7Z7a7h7o7v7}7" ascii
        $s7 = "ConsoleWindowClass" ascii
        $s8 = "NetSupport Ltd" wide
        $s9 = "remcmdstub.exe" ascii
        $s10 = "1C1H1O1U1 2]2t2" ascii
        $s11 = "nKERNEL32.DLL" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
