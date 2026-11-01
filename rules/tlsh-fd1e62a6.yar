rule Sightlines_tlsh_fd1e62a6_asyncrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-fd1e62a6"
        date = "2026-10-20"
        campaign = "tlsh-fd1e62a6"
        family = "asyncrat"
        hash = "2afe1e0fc216a059f2a7210b241b0d1b0e47135691a90ed3bfdbb574052d8843"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-fd1e62a6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " \"$&(*,.02468:<>@BDFHJLNPRTVXZ\\^`bdfhjlnprtvxz|~" ascii
        $s1 = "      <activeCodePage xmlns=\"http://schemas.microsoft.com/SMI/2019/WindowsSettings\">UTF-8</activeCod" ascii
        $s2 = "  <assemblyIdentity type=\"win32\" name=\"Peridot.DesktopUtility\" version=\"3.2.0.0\" processorArchitectu" ascii
        $s3 = "Reserving %zd bytes (%.3f mb) for GC bookkeeping failed" ascii
        $s4 = "System.Text.Json.JsonSerializer.IsReflectionEnabledByDefault" ascii
        $s5 = "System.Linq.Expressions.CanEmitObjectArrayDelegate" ascii
        $s6 = "Committing %zd bytes (%.3f mb) for GC bookkeeping element#%d failed" ascii
        $s7 = "System.ComponentModel.TypeConverter.EnableUnsafeBinaryFormatterInDesigntimeLicenseContextSerializati" ascii
        $s8 = "Process is terminating due to StackOverflowException." ascii
        $s9 = "InternalHijack: TgtThread = %llx, IP = %p" ascii
        $s10 = "Lock_Enter_WaiterCountOverflow_OutOfMemoryException" wide
        $s11 = "System.Threading.Lock.AdaptiveSpinPeriod" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1918976 and 12 of them
}
