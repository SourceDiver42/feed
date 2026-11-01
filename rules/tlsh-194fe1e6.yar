rule Sightlines_tlsh_194fe1e6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-194fe1e6"
        date = "2026-11-01"
        campaign = "tlsh-194fe1e6"
        family = ""
        hash = "335a02dfe9bb67f7351d038d6527c7f6467e08d0173e49a88733ebfa30d7aaa7"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-194fe1e6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "      <!--<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\" />-->" ascii
        $s2 = "      <!--<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\" />-->" ascii
        $s3 = "      <!--<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\" />-->" ascii
        $s4 = "      <!--<supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\" />-->" ascii
        $s5 = "      <!--<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\" />-->" ascii
        $s6 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s7 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\">" ascii
        $s8 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s9 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s10 = "       Makes the application long-path aware. See https://docs.microsoft.com/windows/win32/fileio/ma" ascii
        $s11 = "       also set the 'EnableWindowsFormsHighDpiAutoResizing' setting to 'true' in their app.config. " ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
