rule Sightlines_tlsh_890d3f0e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-890d3f0e"
        date = "2026-10-30"
        campaign = "tlsh-890d3f0e"
        family = ""
        hash = "22b4dd9438c69fedebb1403362590bb8679b01a17c51b4dffa1ffcb2119a93ce"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-890d3f0e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s1 = "GCC: (Rev5, Built by MSYS2 project) 16.1.0" ascii
        $s2 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s3 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s4 = "      <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s5 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s6 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s7 = "      <!--The ID below indicates application support for Windows 10 -->" ascii
        $s8 = "      <!--The ID below indicates application support for Windows 8 -->" ascii
        $s9 = "      <!--The ID below indicates application support for Windows 7 -->" ascii
        $s10 = "Error cleaning up spin_keys for thread %lu." ascii
        $s11 = "      <!--The ID below indicates application support for Windows Vista -->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 10 of them
}
