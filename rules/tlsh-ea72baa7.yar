rule Sightlines_tlsh_ea72baa7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ea72baa7"
        date = "2026-10-28"
        campaign = "tlsh-ea72baa7"
        family = ""
        hash = "5d8dd29325e39d8721b47ce814c4875a30bbaef34844354b1888fa08661d92d2"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ea72baa7.json"
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
        $s10 = "efdDfge$ghfDhig" ascii
        $s11 = "STRDTUS$UVTDVWU" ascii
    condition:
        filesize < 9125888 and 12 of them
}
