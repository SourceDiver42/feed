rule Sightlines_imphash_98b9d99e_dcrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-98b9d99e"
        date = "2026-10-26"
        campaign = "imphash-98b9d99e"
        family = "dcrat"
        hash = "10ff3c82edf92620726c77b368918b64f0744c2cf3cb422279d43cb539fa5cec"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-98b9d99e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "-,43537698;:BAFEGEHEIEJELKMLNKOKQPUTWVXVYVZV[V]\\^\\_\\`\\baedfegdhgigjgkglgmdnmodpdqdrdsdutwvyxzx{x|x~}" wide
        $s1 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" ascii
        $s2 = "<style>body{font-family:\"Arial\";font-size:12;}</style>" wide
        $s3 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" ascii
        $s4 = "D:\\Projects\\WinRAR\\sfx\\build\\sfxrar32\\Release\\sfxrar.pdb" ascii
        $s5 = "    <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s6 = "<asmv3:application xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s7 = "<description>WinRAR SFX module</description>" ascii
        $s8 = "    <!--The ID below indicates application support for Windows 10 -->" ascii
        $s9 = "manually.</li><br><br>8<li>If the destination folder does not exist, it will be" wide
        $s10 = "    <!--The ID below indicates application support for Windows 7 -->" ascii
        $s11 = "    <!--The ID below indicates application support for Windows 8 -->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2434310 and 12 of them
}
