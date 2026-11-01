rule Sightlines_imphash_fc7a3b6e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-fc7a3b6e"
        date = "2026-10-30"
        campaign = "imphash-fc7a3b6e"
        family = ""
        hash = "3949cb6ae3d4b4ac48f56d12ed94505835f59852f3127adc56452de579dfee18"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-fc7a3b6e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s1 = "GCC: (Rev5, Built by MSYS2 project) 16.1.0" ascii
        $s2 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s3 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s4 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s5 = "      <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s6 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s7 = "      <!--The ID below indicates application support for Windows 10 -->" ascii
        $s8 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
        $s9 = "      <!--The ID below indicates application support for Windows 8 -->" ascii
        $s10 = "      <!--The ID below indicates application support for Windows 7 -->" ascii
        $s11 = "      <!--The ID below indicates application support for Windows Vista -->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
