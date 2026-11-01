rule Sightlines_tlsh_505076db_adwareoffercore
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-505076db"
        date = "2026-10-31"
        campaign = "tlsh-505076db"
        family = "adwareoffercore"
        hash = "023120cef031fb5530d0c3c36fec36ff413583ab72f4f93dbc40208d4902e8dc"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-505076db.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "<file name=\"textshaping.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s3 = "<file name=\"winhttp.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s4 = "%TObjectList<System.Classes.TRegGroup>4EH" ascii
        $s5 = "Embarcadero Delphi for Win32 compiler version 36.0 (29.0.55362.2017)" ascii
        $s6 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s7 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s8 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s9 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s10 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>'" ascii
        $s11 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>'" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 5893894 and 12 of them
}
