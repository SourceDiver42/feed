rule Sightlines_imphash_a3bf3688_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a3bf3688"
        date = "2026-10-30"
        campaign = "imphash-a3bf3688"
        family = ""
        hash = "04ec49b1670f764f0a2a17752afccfadfe5b5efbcefcb9b7c7276b16f23757f3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a3bf3688.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s1 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s2 = "Copyright (C) 1993-2021 Werner Almesberger and Craig Small" ascii
        $s3 = "  -Z,--context REGEXP kill only process(es) having context" ascii
        $s4 = "PSmisc comes with ABSOLUTELY NO WARRANTY." ascii
        $s5 = "      <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s6 = "      <!--The ID below indicates application support for Windows 10 -->" ascii
        $s7 = "  -s,--signal SIGNAL  send this signal instead of SIGTERM" ascii
        $s8 = "      <!--The ID below indicates application support for Windows 8 -->" ascii
        $s9 = "      <!--The ID below indicates application support for Windows 7 -->" ascii
        $s10 = "      <!--The ID below indicates application support for Windows Vista -->" ascii
        $s11 = "For more information about these matters, see the files named COPYING." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
