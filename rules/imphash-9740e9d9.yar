rule Sightlines_imphash_9740e9d9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9740e9d9"
        date = "2026-10-30"
        campaign = "imphash-9740e9d9"
        family = ""
        hash = "0d88aab8e70e331584292ca81aae5eafbcab5cfb881204dfb221bd6248b83871"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-9740e9d9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s3 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s4 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s5 = "        <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
        $s6 = "FastMM Borland Edition (c) 2004 - 2008 Pierre le Riche / Professional Software Development" ascii
        $s7 = "For more detailed information, please visit http://www.jrsoftware.org/ishelp/index.php?topic=setupcm" wide
        $s8 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" ascii
        $s9 = "/MERGETASKS=\"comma separated list of task names\"" wide
        $s10 = "/COMPONENTS=\"comma separated list of component names\"" wide
        $s11 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 41184242 and 12 of them
}
