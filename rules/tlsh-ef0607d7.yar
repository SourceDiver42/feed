rule Sightlines_tlsh_ef0607d7_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ef0607d7"
        date = "2026-11-01"
        campaign = "tlsh-ef0607d7"
        family = "remcos"
        hash = "11862191bdcfc8bb03d5e7e1f72a1db133eaaca9344916a6c79c3517f7aba06d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ef0607d7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Copyright (c) by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." ascii
        $s1 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii
        $s2 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" wide
        $s3 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" wide
        $s4 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(Wscript.ScriptFullName)" wide
        $s5 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\" wide
        $s6 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii
        $s7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide
        $s8 = "C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE33" ascii
        $s9 = "fso.DeleteFile(Wscript.ScriptFullName)" wide
        $s10 = "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296" ascii
        $s11 = "11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD07613" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1220688 and 12 of them
}
