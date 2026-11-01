rule Sightlines_dotnet_typelib_guid_6a4fa696_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-6a4fa696"
        date = "2026-11-01"
        campaign = "dotnet_typelib_guid-6a4fa696"
        family = ""
        hash = "08bed8100f8732e0c95846ea6a87f0c04559cb38ba5e4825b0248a5a5e94051c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-6a4fa696.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <dpiAware xmlns=\"http://schemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware>" ascii
        $s1 = "NXFuscator [ Free obfuscator ] v1.0.0.2 | Discord https://discord.gg/sU6Cv4MGev" ascii
        $s2 = "      <!--<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\" />-->" ascii
        $s3 = "      <!--<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\" />-->" ascii
        $s4 = "      <!--<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\" />-->" ascii
        $s5 = "      <!--<supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\" />-->" ascii
        $s6 = "      <!--<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\" />-->" ascii
        $s7 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s8 = "<assembly manifestVersion=\"1.0\" xmlns=\"urn:schemas-microsoft-com:asm.v1\">" ascii
        $s9 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s10 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s11 = "$WDLoader.Program+<BlockAvSites>d__16" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
