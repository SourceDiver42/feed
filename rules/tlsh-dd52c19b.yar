rule Sightlines_tlsh_dd52c19b_njrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-dd52c19b"
        date = "2026-10-28"
        campaign = "tlsh-dd52c19b"
        family = "njrat"
        hash = "165619e61ebf6feb78b2b78f1fa407540e71712e6fe8185bb810c8dffd54eaff"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-dd52c19b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "cmd /c reg ADD HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System /v EnableLUA /t REG_DW" wide
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "cmd /c rundll32.exe user32.dll,LockWorkStation" wide
        $s5 = "cmd /c powershell Set-MpPreference -DisableRealtimeMonitoring $true" wide
        $s6 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" ascii
        $s7 = "Cannot overwrite MBR, needs Admin privilege" wide
        $s8 = "As you reboot, you find that your MBR has been overwritten." ascii
        $s9 = "AdminCheck: Can't use MBR. (No admin)" wide
        $s10 = "BluetoothNotificationAreaIconWindowClass" wide
        $s11 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
