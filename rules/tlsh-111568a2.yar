rule Sightlines_tlsh_111568a2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-111568a2"
        date = "2026-10-31"
        campaign = "tlsh-111568a2"
        family = ""
        hash = "1f097ff565059147be68fdac148db435eaf9c2dd0a6f8248369e818f2cada590"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-111568a2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "System.Diagnostics.Tracing.EventKeywords, System.Diagnostics.Tracing, Version=10.0.0.0, Culture=neut" ascii
        $s4 = "ISystem.Net.Sockets.SocketAsyncEventArgs+<<DnsConnectAsync>g__Core|113_0>d" ascii
        $s5 = "8System.Net.Sockets.Socket+<<ConnectAsync>g__Core|293_0>d" ascii
        $s6 = "=System.Net.Sockets.Socket+<AcceptAndReceiveHelperAsync>d__207" ascii
        $s7 = "Only use with Socket.Blocking=false on WASI" wide
        $s8 = "/_/src/runtime/artifacts/obj/System.Net.Sockets/Release/net10.0-windows/System.Net.Sockets.pdb" ascii
        $s9 = "5464748494:4<;=;>;?;@;A;JIKIMLPOQO[Z\\Zdc" wide
        $s10 = "<CompleteCore>g__CleanupIOCPResult|169_0" ascii
        $s11 = "<DoOperationReceiveMessageFrom>g__Core|150_0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1061392 and 12 of them
}
