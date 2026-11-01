rule Sightlines_imphash_67d2dbca_stealc
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-67d2dbca"
        date = "2026-10-27"
        campaign = "imphash-67d2dbca"
        family = "stealc"
        hash = "095aaaa3cd9bb371eb912452ea29d6d12e907fcd4a7cdcefff1e44675c3bb4f6"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-67d2dbca.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s1 = "    <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s2 = "$NT Shutdown: OpenProcessToken error.)NT Shutdown: AdjustTokenPrivileges error.!NT Shutdown: ExitWin" wide
        $s3 = "/T:<full path> -- Specifies temporary working folder," wide
        $s4 = "            <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s5 = "    <!-- This Id value indicates the application supports Windows Blue/Server 2012 R2 functionality-" ascii
        $s6 = "            <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s7 = "    <compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"> " ascii
        $s8 = "rundll32.exe %sadvpack.dll,DelNodeRunDLL32 \"%s\"" ascii
        $s9 = "/C:<Cmd> -- Override Install Command defined by author." wide
        $s10 = "            <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/> " ascii
        $s11 = "rundll32.exe %s,InstallHinfSection %s 128 %s" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 25165824 and 12 of them
}
