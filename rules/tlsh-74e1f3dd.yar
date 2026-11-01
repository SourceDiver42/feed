rule Sightlines_tlsh_74e1f3dd_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-74e1f3dd"
        date = "2026-10-31"
        campaign = "tlsh-74e1f3dd"
        family = ""
        hash = "a82af566588f39ffb9f59303f537462fe7ab3e4e0557ec7ec375a18651bd833f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-74e1f3dd.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "PSystem.Net.WebSockets.ManagedWebSocket+<CloseWithReceiveErrorAndThrowAsync>d__67" ascii
        $s1 = "GSystem.Net.WebSockets.ManagedWebSocket+<EnsureBufferContainsAsync>d__72" ascii
        $s2 = "BSystem.Net.WebSockets.ManagedWebSocket+<CloseOutputAsyncCore>d__50" ascii
        $s3 = "?System.Net.WebSockets.ManagedWebSocket+<CloseAsyncPrivate>d__69" ascii
        $s4 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s5 = "ISystem.Net.WebSockets.ManagedWebSocket+<HandleReceivedPingPongAsync>d__65" ascii
        $s6 = "CSystem.Net.WebSockets.ManagedWebSocket+<ReceiveAsyncPrivate>d__61`1" ascii
        $s7 = "QSystem.Net.WebSockets.ManagedWebSocket+<WaitForServerToCloseConnectionAsync>d__64" ascii
        $s8 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s9 = "CSystem.Net.WebSockets.ManagedWebSocket+<WaitForWriteTaskAsync>d__56" ascii
        $s10 = "FSystem.Net.WebSockets.ManagedWebSocket+<HandleReceivedCloseAsync>d__63" ascii
        $s11 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
