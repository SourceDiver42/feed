rule Sightlines_tlsh_ae5eb87f_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-ae5eb87f"
        date = "2026-10-21"
        campaign = "tlsh-ae5eb87f"
        family = "agenttesla"
        hash = "6772c041440cf1f4fb5e6590bfd3e5902a6080aa46e4131277f22f33ca702e32"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-ae5eb87f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " \"$&(*,.02468:<>@BDFHJLNPRTVXZ\\^`bdfhjlnprtvxz|~" ascii
        $s1 = "      <activeCodePage xmlns=\"http://schemas.microsoft.com/SMI/2019/WindowsSettings\">UTF-8</activeCod" ascii
        $s2 = "80},\"CardTableInfo\":{\"!\":24,\"Recount\":0,\"Size\":8,\"NextCardTable\":16},\"RegionFreeList\":{\"!\":56,\"HeadF" ascii
        $s3 = "served\":16,\"Allocated\":24,\"GcIndex\":32,\"Fgm\":40,\"Size\":48,\"AvailablePagefileMb\":56,\"LohP\":64},\"Handl" ascii
        $s4 = "4,\"Mem\":32,\"Flags\":40,\"Next\":48,\"BackgroundAllocated\":56},\"OomHistory\":{\"Reason\":0,\"AllocSize\":8,\"Re" ascii
        $s5 = "egionKinds\":\"0x3\",\"GCHeapMarkArray\":[[1],\"pointer\"],\"GCHeapNextSweepObj\":[[2],\"pointer\"],\"GCHeapBack" ascii
        $s6 = "},\"TableSegment\":{\"NextSegment\":1998,\"RgAllocation\":480,\"RgTail\":1920,\"RgValue\":4096,\"RgUserData\":16" ascii
        $s7 = "ismBitsLength\":\"0x2\",\"GlobalMechanismsLength\":\"0x6\",\"InitialHandleTableArraySize\":\"0xa\",\"DebugDestro" ascii
        $s8 = "alTypes\":\"0xd\",\"HandlesPerBlock\":\"0x40\",\"BlockInvalid\":\"0xff\",\"CardTableInfoSize\":\"0x18\",\"CountFreeR" ascii
        $s9 = "groundMinSavedAddr\":[[3],\"pointer\"],\"GCHeapBackgroundMaxSavedAddr\":[[4],\"pointer\"],\"GCHeapAllocAlloc" ascii
        $s10 = "ExpandMechanisms\":[[13],\"pointer\"],\"GCHeapInterestingMechanismBits\":[[14],\"pointer\"],\"GCHeapFreeable" ascii
        $s11 = "  <assemblyIdentity type=\"win32\" name=\"Citrine.DesktopUtility\" version=\"3.2.0.0\" processorArchitectu" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 4482948 and 12 of them
}
