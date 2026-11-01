rule Sightlines_imphash_a4deb495_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-a4deb495"
        date = "2026-10-30"
        campaign = "imphash-a4deb495"
        family = ""
        hash = "5acd89f57b2d1ec5a0972323d72956943320b6aba77147561b9f64d666cc4316"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-a4deb495.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ility=\"urn:schemas-microsoft-com:compatibility.v1\" Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"></ms_" ascii
        $s1 = "pplication xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAwareness xmlns=\"http://sch" ascii
        $s2 = "emas.microsoft.com/SMI/2016/WindowsSettings\">PerMonitorV2</dpiAwareness></windowsSettings></applicat" ascii
        $s3 = ".?AV?$_Ref_count_resource@PEAUFlutterDesktopMessenger@@P6AXPEAU1@@Z@std@@" ascii
        $s4 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schem" ascii
        $s5 = "Copyright (C) 2026 levvs-one. MIT License." wide
        $s6 = "ibility=\"urn:schemas-microsoft-com:compatibility.v1\"><ms_compatibility:supportedOS xmlns:ms_compatib" ascii
        $s7 = "as-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"requireAdmin" ascii
        $s8 = "v1\" xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><ms_compatibility:application xmlns:ms_compat" ascii
        $s9 = "?_Raise_handler@std@@3P6AXAEBVexception@stdext@@@ZEA" ascii
        $s10 = "istrator\" uiAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><a" ascii
        $s11 = ".?AV?$_Ref_count_obj2@VFlutterEngine@flutter@@@std@@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
