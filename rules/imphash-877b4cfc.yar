rule Sightlines_imphash_877b4cfc_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-877b4cfc"
        date = "2026-10-30"
        campaign = "imphash-877b4cfc"
        family = ""
        hash = "34b78a64d76e3d03455fa25dda4292eea59dea145f0c3f2c2addcb7380ff988b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-877b4cfc.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">" ascii
        $s1 = "D:\\Projects\\WinRAR\\SFX\\build\\sfxrar64\\Release\\sfxrar.pdb" ascii
        $s2 = "<style>body{font-family:\"Arial\";font-size:12;}</style>" wide
        $s3 = "JNot enough memory to unpack the archive with %u GB compression dictionary.+64-bit self-extracting m" wide
        $s4 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" ascii
        $s5 = "<html><head><meta http-equiv=\"content-type\" content=\"text/html; charset=utf-8\"></head>" wide
        $s6 = "    <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s7 = "<asmv3:application xmlns:asmv3=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s8 = "manually.</li><br><br>8<li>If the destination folder does not exist, it will be2created automaticall" wide
        $s9 = "<description>WinRAR SFX module</description>" ascii
        $s10 = "    <!--The ID below indicates application support for Windows 10 -->" ascii
        $s11 = "    <!--The ID below indicates application support for Windows 7 -->" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 29383750 and 12 of them
}
