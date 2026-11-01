rule Sightlines_imphash_1aa37283_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-1aa37283"
        date = "2026-10-22"
        campaign = "imphash-1aa37283"
        family = ""
        hash = "00eb23895750f2ea8aa5dae08aa7120846404596f1ade0b142461597b4157ffe"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-1aa37283.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Add-Type -AssemblyName PresentationFramework;[System.Windows.MessageBox]::Show($env:SERO_MSG,'Notifi" wide
        $s1 = "[MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)]public string dmDeviceName;" wide
        $s2 = "@<EstablishProxyTunnelAsync>d__576<EstablishSocksTunnel>d__58:<HandleHttp11Downgrade>d__105J<InjectN" ascii
        $s3 = "[MarshalAs(UnmanagedType.ByValTStr,SizeConst=32)]public string dmFormName;" wide
        $s4 = ".<>c__DisplayClass68_0`1\"<get_Claims>d__914AllowedBmpCodePointsBitmap2OptimizedInboxTextEncoder0Defa" ascii
        $s5 = "r<<GetAddrInfoWithTelemetryAsync>g__CompleteAsync|35_0>d`1.<>c__DisplayClass40_0`1$GetAddrInfoExStat" ascii
        $s6 = "Z<WaitForExitAsync>g__WaitUntilOutputEOF|186_1Z<GetProcessHandlePairs>g__SafeGetHandle|273_0" ascii
        $s7 = "[WinApi]::EnumDisplaySettings([System.IntPtr]::Zero,-1,[ref]$dm)|Out-Null;" wide
        $s8 = "J<CleanCacheAndDisposeIfUnused>b__65_0,<HandleAltSvc>b__138_08TryGetChallengeDataForScheme" ascii
        $s9 = "$f.Query = \"SELECT * FROM __InstanceModificationEvent WITHIN 30 WHERE TargetInstance ISA 'Win32_Perf" wide
        $s10 = "@<FlushAsyncInternal>g__Core|79_0j<ThrowIfDisposed>g__ThrowObjectDisposedException|80_0" ascii
        $s11 = "H<IsPreamble>g__IsPreambleWorker|57_0j<ThrowIfDisposed>g__ThrowObjectDisposedException|73_0@" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 17805312 and 12 of them
}
