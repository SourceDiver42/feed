rule Sightlines_imphash_15c59c97_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-15c59c97"
        date = "2026-10-24"
        campaign = "imphash-15c59c97"
        family = ""
        hash = "052a2258a185f4c858326ff1a5754b2c4c2bf680c12ebf30a3c2b2b9c1af8f68"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-15c59c97.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "host.UI.RawUI.BufferSize = new-object System.Management.Automation.Host.Size(1024,50);\" \"&\"\"%s\"\"\" 2>" wide
        $s1 = ".?AV<lambda_1>@?1??OnPropChanged@WinRTControlBase@@AAE_NABVEvent@exui@@@Z@" ascii
        $s2 = ".?AV<lambda_1>@?1??UpdateFromProperty@ComboBoxControlWinRT@@UAE_NXZ@" ascii
        $s3 = "Caphyon\\Advanced Installer\\[ProductCode]\\[AI_EXTERNALUIUNINSTALLERNAME]" wide
        $s4 = ".?AV<lambda_1>@?1??UpdateWindowText@TextControlWinRT@@UAEXABV?$basic_string@_WU?$char_traits@_W@std@" ascii
        $s5 = ".?AV<lambda_1>@?1??InitControl@CheckBoxControlWinRT@@UAEXXZ@" ascii
        $s6 = ".?AV<lambda_1>@?1??SetAsDefaultButton@ImageButtonControlWinRT@@EAE_N_N@Z@" ascii
        $s7 = ".?AV<lambda_1>@?1??SetAsDefaultButton@PushButtonControlWinRT@@EAE_N_N@Z@" ascii
        $s8 = ".?AV<lambda_1>@?6??OnDdx@WinRTControlBase@@AAE_NABVEvent@exui@@@Z@" ascii
        $s9 = ".?AV<lambda_1>@?1??ShowControl@WinRTControlBase@@UAEX_N@Z@" ascii
        $s10 = ".?AV<lambda_1>@?1??DoSaveData@ComboBoxControlWinRT@@UAE_NXZ@" ascii
        $s11 = ".?AV<lambda_1>@?1??SetPos@ProgressBarWinRT@@UAEXI@Z@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 27452032 and 12 of them
}
