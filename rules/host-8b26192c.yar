rule Sightlines_host_8b26192c_connectwise
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-8b26192c"
        date = "2026-10-30"
        campaign = "host-8b26192c"
        family = "connectwise"
        hash = "6589542a7d78bb4250aeced8d0fcaf39412d0d4109da215ebac8b451455fdab9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-8b26192c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "DZ%2bRUZivgpE7y0X4fYo4M6bUzqF270L86fEky56hCfnKx7yHwfivCF3hpK32keKJaTQMZaRTss71Q67bue%2b&c=Popepagasc" ascii
        $s1 = "5HaW6NUvVBNanOktNoGN6MlB%2fZFcrVcBkVo%2bg7Tplc7cIEjX5ySYVXdNxl6AbvEM4GGFXa8FzZMTY%2fGqCG%2bA9PSuhaeP" ascii
        $s2 = "u1QoFTEKJdXAZWlvAj5TURlrnXTyMacm6EeArQ3ebqjOcjGKeHt9MKYObZ%2bVVuRwlluoTBp22%2bbFk%2fQqeoSVqjnBkXH3ox" ascii
        $s3 = "24?69<>BNPREDHKMY_aTVX[]dftsihlnprvw$&($&(|{" wide
        $s4 = "394821E67B}NOT EXCLUDE_BACKSTAGE_SHELLScreenConnect.WindowsBackstageShell.exeFileManagerFiles{80C42F" ascii
        $s5 = "8B}OLD_PRODUCT_2OLD_PRODUCT_3NEW_VERSIONScreenConnect Client (d08195f142b8bd3b){FBD21F66-4927-CEE9-D" ascii
        $s6 = "E1-27A8-4EB1-896F-161D3237D864}NOT EXCLUDE_FILE_MANAGERScreenConnect.WindowsFileManager.exeServiceFi" ascii
        $s7 = "B6E27BUseOriginalUrlEncoding#1regED314AE69CE5D835D523FB365C82C36B[URL_SCHEME]\\shell\\open\\command\"[IN" ascii
        $s8 = "ationPackage.dllCredentialProviderFiles{595C1B10-5F3C-42F7-B006-5D9C44DEC4FF}NOT EXCLUDE_CREDENTIAL_" ascii
        $s9 = "TNetFramework40ClientCustomActionLibraryWixCAMainFiles{E0EF5F66-7B92-40DE-8B20-EB91E1C859BB}INSTALLL" ascii
        $s10 = "-4CD4-A165-9D92784D1A1F}SERVICE_CLIENT_LAUNCH_PARAMETERS?e=Access&y=Guest&h=167.94.158.48&p=8041&k=B" ascii
        $s11 = "ntVersion\\Authentication\\Credential Providers\\[CREDENTIAL_PROVIDER_CLASS_ID]reg685500C4A1A36BBDF1BB3" ascii
    condition:
        filesize < 27090944 and 12 of them
}
