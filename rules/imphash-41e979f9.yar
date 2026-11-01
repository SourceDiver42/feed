rule Sightlines_imphash_41e979f9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-41e979f9"
        date = "2026-10-30"
        campaign = "imphash-41e979f9"
        family = ""
        hash = "195f4be6df6d6c864bf479a4dca1bc540679856c3ae5b082648db108d903bc3f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-41e979f9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s1 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s2 = "Copyright (C) 1993-2021 Werner Almesberger and Craig Small" ascii
        $s3 = "  -Z,--context REGEXP kill only process(es) having context" ascii
        $s4 = "PSmisc comes with ABSOLUTELY NO WARRANTY." ascii
        $s5 = "      <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s6 = "GCC: (GNU) 11.2.0 20210728 (Fedora Cygwin 11.2.0-2)" ascii
        $s7 = "      <!--The ID below indicates application support for Windows 10 -->" ascii
        $s8 = "  -s,--signal SIGNAL  send this signal instead of SIGTERM" ascii
        $s9 = "      <!--The ID below indicates application support for Windows 8 -->" ascii
        $s10 = "      <!--The ID below indicates application support for Windows 7 -->" ascii
        $s11 = "      <!--The ID below indicates application support for Windows Vista -->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
