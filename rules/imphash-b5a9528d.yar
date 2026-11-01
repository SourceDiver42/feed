rule Sightlines_imphash_b5a9528d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-b5a9528d"
        date = "2026-10-30"
        campaign = "imphash-b5a9528d"
        family = ""
        hash = "1f72ca72dae9ef8bc6f13cf87c205998befdc7ddc6fe5445c9333089368a05e7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-b5a9528d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "command line encoding conversion failure" ascii
        $s1 = "Windows original main args:" ascii
        $s2 = "OpenJDK Platform binary" wide
        $s3 = "http://www.eclipse.org/0" ascii
        $s4 = "JLI_InitArgProcessing" ascii
        $s5 = "_JAVA_LAUNCHER_DEBUG" ascii
        $s6 = "Eclipse Adoptium" wide
        $s7 = "JLI_GetStdArgc" ascii
        $s8 = "JLI_GetStdArgs" ascii
        $s9 = "380114235959Z0i1" ascii
        $s10 = "JLI_CmdToArgs" ascii
        $s11 = "360903235959Z0c1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 9 of them
}
