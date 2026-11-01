rule Sightlines_tlsh_9008fdae_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-9008fdae"
        date = "2026-10-31"
        campaign = "tlsh-9008fdae"
        family = ""
        hash = "128aee8c62a673d64739e585e3876b61133571cec83a46240a62581d5465639b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-9008fdae.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "wnObject\":[344,\"GCHandle\"],\"LinkNext\":[120,\"pointer\"],\"ThreadLocalDataPtr\":592,\"TEB\":48},\"ThreadStor" ascii
        $s1 = "g\":64,\"_remoteStackTraceString\":72,\"_HResult\":108,\"_xcode\":104},\"ExceptionInfo\":{\"ThrownObject\":8,\"P" ascii
        $s2 = "TAStackCrawlCallBack: STACKCRAWL method:%pM ('%s'), offset %x, Frame:%p, FrameIdentifier = %s" ascii
        $s3 = "oken\":40},\"FnPtrTypeDesc\":{\"NumArgs\":24,\"CallConv\":28,\"RetAndArgTypes\":32,\"LoaderModule\":16},\"Dynami" ascii
        $s4 = "ReadyToRunInfo\":608,\"GrowableSymbolStream\":336,\"AvailableTypeParams\":528,\"InstMethodHashTable\":584,\"" ascii
        $s5 = "reviousNestedInfo\":0},\"GCHandle\":{\"!\":8},\"Object\":{\"m_pMethTab\":0},\"String\":{\"m_FirstChar\":12,\"m_Str" ascii
        $s6 = "onNode\":{\"VersionId\":16,\"Next\":24,\"RejitState\":32},\"ProfControlBlock\":{\"GlobalEventMask\":1888},\"Fram" ascii
        $s7 = "gException\":1350},\"ResumableFrame\":{\"!\":24,\"TargetContextPtr\":16},\"HijackFrame\":{\"!\":40,\"ReturnAddre" ascii
        $s8 = "t\":1768,\"HighFrequencyHeap\":696,\"LowFrequencyHeap\":688,\"StubHeap\":712},\"PEAssembly\":{\"PEImage\":8,\"As" ascii
        $s9 = "robeExtensionResult\":40},\"PEImageLayout\":{\"Base\":8,\"Size\":16,\"Flags\":20},\"CGrowableSymbolStream\":{\"B" ascii
        $s10 = "layLoadMethodCallThunks\":112,\"EntryPointToMethodDescMap\":336},\"ReadyToRunHeader\":{\"MajorVersion\":4,\"" ascii
        $s11 = "s\":0},\"EEClass\":{\"MethodTable\":16,\"MethodDescChunk\":32,\"NumMethods\":68,\"FieldDescList\":24,\"CorTypeAt" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 9475600 and 12 of them
}
