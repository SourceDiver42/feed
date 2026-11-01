rule Sightlines_tlsh_c0865bf8_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c0865bf8"
        date = "2026-10-31"
        campaign = "tlsh-c0865bf8"
        family = ""
        hash = "7875941c62c402cbb1f3505883bf87ed74088f18171ff3a66d8c8fa06e511836"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c0865bf8.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "OSystem.IO.Pipelines.PipeWriterStream+<<GetFlushResultAsTask>g__AwaitTask|29_0>d" ascii
        $s1 = ">System.IO.Pipelines.PipeReader+<<CopyToAsync>g__Awaited|15_1>d" ascii
        $s2 = "7System.IO.Pipelines.PipeReader+<CopyToAsyncCore>d__16`1" ascii
        $s3 = "7System.IO.Pipelines.StreamPipeReader+<CopyToAsync>d__41" ascii
        $s4 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s5 = "3System.IO.Pipelines.PipeWriter+<CopyFromAsync>d__14" ascii
        $s6 = "<IsDefaultSharedMemoryPool>k__BackingField" ascii
        $s7 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s8 = ">System.IO.Pipelines.StreamPipeWriter+<FlushAsyncInternal>d__39" ascii
        $s9 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s10 = "9System.IO.Pipelines.PipeReader+<ReadAtLeastAsyncCore>d__4" ascii
        $s11 = "9System.IO.Pipelines.StreamPipeWriter+<CompleteAsync>d__33" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
