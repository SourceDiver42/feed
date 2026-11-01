rule Sightlines_tlsh_8cfbe6a7_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8cfbe6a7"
        date = "2026-10-22"
        campaign = "tlsh-8cfbe6a7"
        family = "formbook"
        hash = "29215ad7f765f085a93eebf9be3fc2a1c80e38c897b88a92d4b9467bdefc8dd0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8cfbe6a7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Week {0} [CRITICAL ALERT]: Equipment malfunction detected! Nitrate spiked and stress occurred." wide
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "Turnover & Flow: 32.9x | Rating: Exemplary" wide
        $s3 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s5 = "C | Alk 8.6 dKH | Ca 425 ppm | Phase: Pristine" wide
        $s6 = "Dynamic Reef Cross-Section & Sump Ecosystem" wide
        $s7 = "Turnover & Flow: {0:F1}x | Rating: {1}" wide
        $s8 = "KMicrosoft.VisualStudio.Editors.SettingsDesigner.SettingsSingleFileGenerator" ascii
        $s9 = "Week 0: Aquarium baseline re-initialized." wide
        $s10 = "Saltwater Aquarium - Reef Section & Sump Station" wide
        $s11 = "Amphiprion ocellaris, Zebrasoma flavescens" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1673216 and 12 of them
}
