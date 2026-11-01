rule Sightlines_tlsh_c379773e_xworm
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c379773e"
        date = "2026-11-01"
        campaign = "tlsh-c379773e"
        family = "xworm"
        hash = "3d3362f1bd817c6c92aea1a2f3245ffa792c039803c0694319a8adcca57fbf0c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c379773e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "Content-Type: application/x-www-form-urlencoded" wide
        $s4 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" ascii
        $s5 = "SELECT * FROM Win32_VideoController" wide
        $s6 = "-ExecutionPolicy Bypass -File \"" wide
        $s7 = "Win32_Processor.deviceid=\"CPU0\"" wide
        $s8 = "Select * from AntivirusProduct" wide
        $s9 = "m_MyWebServicesObjectProvider" ascii
        $s10 = "OfflineKeylogger Not Enabled" wide
        $s11 = "ThreadSafeObjectProvider`1" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
