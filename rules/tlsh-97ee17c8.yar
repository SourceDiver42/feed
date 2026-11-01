rule Sightlines_tlsh_97ee17c8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-97ee17c8"
        date = "2026-10-31"
        campaign = "tlsh-97ee17c8"
        family = ""
        hash = "4f3f74d9fe5f61cf277a05f9294d7185a78771da186030f498e212785b631522"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-97ee17c8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "%nKind=%1;%nClrInstanceID=%2;%nTypeID=%3;%nTypeName=%4;%nAddress=%5;%nObjectSize=%6;%nSampledByteOff" wide
        $s1 = "WaitSource=%1;%nAssociatedObjectID=%2;%nClrInstanceID=%3" wide
        $s2 = "NativePdbAge=%11;%nNativePdbBuildPath=%12;%nNativeBuildID=%13" wide
        $s3 = "D:\\a\\_work\\1\\s\\src\\runtime\\artifacts\\obj\\coreclr\\windows.x64.Release\\dlls\\clretwrc\\clretwrc.pdb" ascii
        $s4 = "AllocationSamplingKeyword" wide
        $s5 = "ModuleLoadUnloadRundown_V3" wide
        $s6 = "WaitHandleWaitSourceMap" wide
        $s7 = "ModuleLoadUnload_V3" wide
        $s8 = "WaitHandleKeyword" wide
        $s9 = "WaitHandleWaitStop" wide
        $s10 = "AllocationSampled" wide
        $s11 = "SampledByteOffset" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
