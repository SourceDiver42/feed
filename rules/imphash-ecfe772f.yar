rule Sightlines_imphash_ecfe772f_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-ecfe772f"
        date = "2026-10-30"
        campaign = "imphash-ecfe772f"
        family = ""
        hash = "05a6ae375ef48f48f368aa71b7b1aaabd99a55bf9a857c4f0caf57a2878cea27"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-ecfe772f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"> " ascii
        $s1 = " deflate 1.1.4 Copyright 1995-2002 Jean-loup Gailly " ascii
        $s2 = " inflate 1.1.4 Copyright 1995-2002 Mark Adler " ascii
        $s3 = "SOFTWARE\\Microsoft\\.NETFramework\\policy" ascii
        $s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" ascii
        $s5 = "\\Microsoft\\Internet Explorer\\Quick Launch" ascii
        $s6 = "  <description>Smart Install Maker - create setup software</description>" ascii
        $s7 = "Software\\Microsoft\\Windows\\CurrentVersion\\GrpConv\\MapGroups" ascii
        $s8 = "        <requestedExecutionLevel level=\"requireAdministrator\"/>" ascii
        $s9 = "The setup files are corrupted. Please obtain a new copy of the program." ascii
        $s10 = "oversubscribed dynamic bit lengths tree" ascii
        $s11 = "This program must be run under Win32" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3687060 and 12 of them
}
