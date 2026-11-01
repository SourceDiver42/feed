rule Sightlines_tlsh_322cdf80_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-322cdf80"
        date = "2026-10-16"
        campaign = "tlsh-322cdf80"
        family = ""
        hash = "0f8976cee8d60f7c8c2826f36db4a09f30fff94effb652cabca2efda9b4c2bf2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-322cdf80.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "'System.Globalization.DateTimeFormatInfo+" ascii
        $s5 = "+System.Globalization.GregorianCalendarTypes" ascii
        $s6 = "matInfo&System.Globalization.GregorianCalendar" ascii
        $s7 = "(System.Globalization.DateTimeFormatFlags" ascii
        $s8 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s9 = "Izvoz nije uspio ili datoteka ne zadovoljava XSD." wide
        $s10 = "ene zadane vrijednosti (nisu spremljene)." wide
        $s11 = "FAD8FE75086C160174BE22832BEBEBC9DA04C4CB395275AD8ADB10EA3A949B3F" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1713152 and 12 of them
}
