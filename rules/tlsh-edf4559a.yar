rule Sightlines_tlsh_edf4559a_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-edf4559a"
        date = "2026-10-23"
        campaign = "tlsh-edf4559a"
        family = "connectwise"
        hash = "1f01ff480f1e0efd0361c7647b1d8de8b8a0b086a4864fe7d65f1ab8f1997c31"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-edf4559a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s1 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s2 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s3 = "ationPackage.dllCredentialProviderFiles{595C1B10-5F3C-42F7-B006-5D9C44DEC4FF}NOT EXCLUDE_CREDENTIAL_" ascii
        $s4 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s5 = "ge.dll]reg86A6324C5FADB6CB634CB54F9A254136CLSID\\[CREDENTIAL_PROVIDER_CLASS_ID][ProductName] Credenti" ascii
        $s6 = "OCATIONNOT EXCLUDE_MAINScreenConnect.ClientService.dllBackstageShellFiles{DDCF1E82-0B14-4C68-A063-33" ascii
        $s7 = "1BB32EEE98CBEDESoftware\\Microsoft\\NET Framework Setup\\NDP\\v2.0.50727InstallSOFTWARE\\Microsoft\\NET Fr" ascii
        $s8 = "\"[INSTALLLOCATION]ScreenConnect.WindowsClient.exe\" \"%1\"reg3831C0C36D9CE44BC3E6FAE6F161BEA8System\\Cur" ascii
        $s9 = "urrentVersion\\Authentication\\Credential Providers\\[CREDENTIAL_PROVIDER_CLASS_ID]reg685500C4A1A36BBDF" ascii
        $s10 = "3BF2B6E27BUseOriginalUrlEncoding#1regED314AE69CE5D835D523FB365C82C36B[URL_SCHEME]\\shell\\open\\command" ascii
        $s11 = "OMODIFYALLUSERS1ManufacturerScreenConnect SoftwareProductCode{B292C5EA-BF5F-4280-B056-1670FB10BB1D}P" ascii
    condition:
        filesize < 19922944 and 12 of them
}
