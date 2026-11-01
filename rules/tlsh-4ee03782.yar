rule Sightlines_tlsh_4ee03782_remcosrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4ee03782"
        date = "2026-10-17"
        campaign = "tlsh-4ee03782"
        family = "remcosrat"
        hash = "710482ef543f6dadf62abd92b4216e18aba48cad65829186fc5c6974d0b852c8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4ee03782.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "https://pro.ip-api.com/line/?key=QPVvv1rHQJD2pd2&fields=25948155" wide
        $s1 = "Copyright (c) by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." ascii
        $s2 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" ascii
        $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System" ascii
        $s4 = "CreateObject(\"WScript.Shell\").Run \"cmd /c \"\"" wide
        $s5 = "Set fso = CreateObject(\"Scripting.FileSystemObject\")" wide
        $s6 = "CreateObject(\"Scripting.FileSystemObject\").DeleteFile(Wscript.ScriptFullName)" wide
        $s7 = "\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" wide
        $s8 = "Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run\\" wide
        $s9 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall" ascii
        $s10 = "\\BraveSoftware\\Brave-Browser\\Application\\brave.exe" wide
        $s11 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1502288 and 12 of them
}
