rule Sightlines_tlsh_036dcb31_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-036dcb31"
        date = "2026-10-23"
        campaign = "tlsh-036dcb31"
        family = "agenttesla"
        hash = "1308da2a18c17d5d7e4e3efa95316f53e2fb981ad9e46cda66c26b18b1faef90"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-036dcb31.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Software\\Microsoft\\Windows Messaging Subsystem\\Profiles\\9375CFF0413111d3B88A00104B2A6676" wide
        $s1 = "HKEY_CURRENT_USER\\Software\\Aerofox\\Foxmail\\V3.1" wide
        $s2 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s3 = "HKEY_CURRENT_USER\\Software\\Aerofox\\FoxmailPreview" wide
        $s4 = "\\VirtualStore\\Program Files (x86)\\FTP Commander Deluxe\\Ftplist.txt" wide
        $s5 = "\\VirtualStore\\Program Files (x86)\\FTP Commander\\Ftplist.txt" wide
        $s6 = "HKEY_CURRENT_USER\\Software\\RimArts\\B2\\Settings" wide
        $s7 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s8 = "SmartFTP\\Client 2.0\\Favorites\\Quick Connect" wide
        $s9 = "Software\\A.V.M.\\Paltalk NG\\common_settings\\core\\users\\creds\\" wide
        $s10 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s11 = "SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
