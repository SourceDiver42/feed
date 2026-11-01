rule Sightlines_imphash_4eb92592_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-4eb92592"
        date = "2026-10-30"
        campaign = "imphash-4eb92592"
        family = ""
        hash = "0d0448174d811b743faed2c1600b6174f33e65506e196b177effe0cd7a04cdb2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-4eb92592.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "command line encoding conversion failure" ascii
        $s1 = "XPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" ascii
        $s2 = "Windows original main args:" ascii
        $s3 = "JLI_InitArgProcessing" ascii
        $s4 = "_JAVA_LAUNCHER_DEBUG" ascii
        $s5 = "JLI_GetStdArgc" ascii
        $s6 = "JLI_GetStdArgs" ascii
        $s7 = "380114235959Z0i1" ascii
        $s8 = "JLI_CmdToArgs" ascii
        $s9 = "360903235959Z0c1" ascii
        $s10 = "JLI_MemAlloc" ascii
        $s11 = "Full Version" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
