rule Sightlines_tlsh_310c3f5a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-310c3f5a"
        date = "2026-10-23"
        campaign = "tlsh-310c3f5a"
        family = ""
        hash = "34d364fb8e3789b2e477e357c78bdeaa2a4cda2da8699c979a2e297d9cddf2e2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-310c3f5a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "        <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s2 = "        <supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s3 = "        <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s4 = "        <supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s5 = "Embarcadero Delphi for Win32 compiler version 33.0 (26.0.36039.7899)" ascii
        $s6 = "<file name=\"netapi32.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s7 = "VTEnumerable<System.Generics.Collections.TPair<System.TypInfo.PTypeInfo,System.string>>'" ascii
        $s8 = "VTEnumerable<System.Generics.Collections.TPair<System.string,System.TypInfo.PTypeInfo>>'" ascii
        $s9 = "        <supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
        $s10 = "<file name=\"version.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
        $s11 = "<file name=\"mpr.dll\" loadFrom=\"%SystemRoot%\\system32\\\" />" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1722368 and 12 of them
}
