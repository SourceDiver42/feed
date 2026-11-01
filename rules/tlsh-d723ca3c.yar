rule Sightlines_tlsh_d723ca3c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d723ca3c"
        date = "2026-10-21"
        campaign = "tlsh-d723ca3c"
        family = ""
        hash = "36ea1095d1be5b0c95ad214745f8622b6eba26d1f944bab8641431c61f11dba0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d723ca3c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "com/sun/jna/platform/win32/WinCrypt$CRYPT_ALGORITHM_IDENTIFIER$ByReference.classPK" ascii
        $s1 = "com/sun/jna/platform/win32/WinCrypt$CERT_STRONG_SIGN_SERIALIZED_INFO$ByReference.classPK" ascii
        $s2 = "com/sun/jna/platform/win32/HighLevelMonitorConfigurationAPI$MC_DISPLAY_TECHNOLOGY_TYPE$ByReference.c" ascii
        $s3 = "com/sun/jna/platform/win32/Winevt$EVT_CHANNEL_CONFIG_PROPERTY_ID.classPK" ascii
        $s4 = "com/sun/jna/platform/win32/WinCrypt$CERT_STRONG_SIGN_PARA$DUMMYUNION.classPK" ascii
        $s5 = "com/sun/jna/platform/win32/Winevt$EVT_SUBSCRIBE_NOTIFY_ACTION.classPK" ascii
        $s6 = "com/sun/jna/platform/win32/HighLevelMonitorConfigurationAPI$MC_DISPLAY_TECHNOLOGY_TYPE.classPK" ascii
        $s7 = "com/sun/jna/platform/win32/WinCrypt$CERT_CHAIN_POLICY_STATUS$ByReference.classPK" ascii
        $s8 = "com/sun/jna/platform/win32/Winsvc$SERVICE_FAILURE_ACTIONS$ByReference.classPK" ascii
        $s9 = "com/sun/jna/platform/win32/WinCrypt$CRYPT_ALGORITHM_IDENTIFIER.classPK" ascii
        $s10 = "com/sun/jna/platform/win32/COM/Wbemcli$WBEM_CONDITION_FLAG_TYPE.classPK" ascii
        $s11 = "com/sun/jna/platform/win32/Winevt$EVT_PUBLISHER_METADATA_PROPERTY_ID.classPK" ascii
    condition:
        filesize < 13260288 and 12 of them
}
