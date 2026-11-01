rule Sightlines_dotnet_typelib_guid_8e5a9a68_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-8e5a9a68"
        date = "2026-10-31"
        campaign = "dotnet_typelib_guid-8e5a9a68"
        family = ""
        hash = "206564eeafdf2c3a277fcd19938713f89c0e66f1f3cb3260c20d0a2042315833"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-8e5a9a68.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<System_Transactions_DtcProxyShim_ResourceManagerNotifyShim>F506C319B94A04264D10902F7E1F34DF57AFEAC6" ascii
        $s1 = "<System_Transactions_DtcProxyShim_DtcInterfaces_ITmNodeName>F83A5FD8143BEEC85074C07122F0B8F7539C6988" ascii
        $s2 = "<System_Transactions_DtcProxyShim_DtcInterfaces_IResourceManager>FE897E5B6029CDA8583BCE2F387D4A8A97A" ascii
        $s3 = "<System_Transactions_DtcProxyShim_DtcInterfaces_IResourceManagerSink>F27BFCAE9FB4597E73042DFBBE3B6C9" ascii
        $s4 = "<System_Transactions_DtcProxyShim_DtcInterfaces_ITransaction>FB743A426B2DB07696CEF15ED76C59A3594F984" ascii
        $s5 = "<System_Transactions_DtcProxyShim_DtcInterfaces_IPrepareInfo>F2B331A3475953ED21DD6863BAC5587A8F19ADB" ascii
        $s6 = "<System_Transactions_DtcProxyShim_Phase0NotifyShim>FCAF6D6532B6DEAD97BAF81D6C20E91901C9925D7D5BEB7FC" ascii
        $s7 = "<System_Transactions_DtcProxyShim_EnlistmentNotifyShim>F47E6FA6FFD0D268549B3DCBFD7D41032D7F1ADAC633B" ascii
        $s8 = "<System_Transactions_DtcProxyShim_DtcInterfaces_ITransactionReceiver>FAB549EE1B28E423434D7E6997F235C" ascii
        $s9 = "<System_Transactions_DtcProxyShim_VoterNotifyShim>FA18C5EDCD51F4A664DC19CC0FA94E2E0E150CD525B2D4C7D4" ascii
        $s10 = "<System_Transactions_DtcProxyShim_DtcInterfaces_ITransactionImport>F136A2D433BF33251E76B0FFABABE4189" ascii
        $s11 = "<System_Transactions_DtcProxyShim_DtcInterfaces_ITransactionExport>FC6641784F50EFBA1BC5C5625F9FC78F6" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1282656 and 12 of them
}
