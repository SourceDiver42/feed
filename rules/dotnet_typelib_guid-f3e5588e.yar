rule Sightlines_dotnet_typelib_guid_f3e5588e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-f3e5588e"
        date = "2026-10-28"
        campaign = "dotnet_typelib_guid-f3e5588e"
        family = ""
        hash = "0d11c4b0ed5b1235e2ab8aa7ab41302acd686617a007157278eb4e58847ab2b2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-f3e5588e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <!--<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>-->" ascii
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "  <!-- Enable themes for Windows common controls and dialogs (Windows XP and later) -->" ascii
        $s5 = "      <!-- If your application is designed to work with Windows 7, uncomment the following supported" ascii
        $s6 = "        <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\" />" ascii
        $s7 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" ascii
        $s8 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s9 = "            Specifying requestedExecutionLevel node will disable file and registry virtualization." ascii
        $s10 = "ll automatically select the most compatible environment.-->" ascii
        $s11 = "      <!-- A list of all Windows versions that this application is designed to work with. Windows wi" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1714176 and 12 of them
}
