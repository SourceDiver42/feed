rule Sightlines_tlsh_ec9ed83c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ec9ed83c"
        date = "2026-11-01"
        campaign = "tlsh-ec9ed83c"
        family = ""
        hash = "29a9c09b499d757b5f5689a280658c5d8941da7039f415b2f01ce6993e3856c0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ec9ed83c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "ShortcutDirectory_TargetHotkeyIcon_IconIndexShowCmdWkDirDisplayResourceDLLDisplayResourceIdDescripti" ascii
        $s1 = "MediaDiskIdLastSequenceDiskPromptCabinetVolumeLabelSource#cab1.cabAdminUISequenceActionConditionSequ" ascii
        $s2 = "SearchPropertySignature_UpgradeUpgradeCodeVersionMinVersionMaxLanguageAttributesRemoveActionProperty" ascii
        $s3 = "ypeStartTypeErrorControlLoadOrderGroupDependenciesStartNamePasswordArgumentsComponent_DescriptionApp" ascii
        $s4 = "enceCostInitializeFileCostCostFinalizeExecuteActionErrorMessageServiceInstallNameDisplayNameServiceT" ascii
        $s5 = "onResourceDLLDescriptionResourceIdInstallExecuteSequenceValidateProductIDInstallValidateInstallIniti" ascii
        $s6 = "alizeProcessComponentsUnpublishFeaturesRemoveRegistryValuesWriteRegistryValuesRegisterUserRegisterPr" ascii
        $s7 = "Installation Database" ascii
        $s8 = " !#+7DMNPUYadg{}" wide
        $s9 = "SummaryInformation" wide
        $s10 = "$hjlnprtvxzi" wide
        $s11 = "@H??wElDj;" ascii
    condition:
        filesize < 6980608 and 11 of them
}
