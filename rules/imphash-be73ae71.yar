rule Sightlines_imphash_be73ae71_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-be73ae71"
        date = "2026-10-30"
        campaign = "imphash-be73ae71"
        family = ""
        hash = "07391591202f8b65645a9ab5b80a43a4477114dd9d72d94e0b88bcd057c1c1c8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-be73ae71.json"
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
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
