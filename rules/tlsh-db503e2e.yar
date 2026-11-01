rule Sightlines_tlsh_db503e2e_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-db503e2e"
        date = "2026-10-31"
        campaign = "tlsh-db503e2e"
        family = ""
        hash = "716f9417ef3b0b230b9dbe23e6b2b092b2fc1a19ea11c018b467e1f30f88b041"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-db503e2e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "=System.Net.Quic.QuicConnection+<OpenOutboundStreamAsync>d__50" ascii
        $s4 = "System.Diagnostics.Tracing.EventKeywords, System.Diagnostics.Tracing, Version=10.0.0.0, Culture=neut" ascii
        $s5 = ">System.Net.Quic.QuicConnection+<AcceptInboundStreamAsync>d__51" ascii
        $s6 = "?System.Net.Quic.QuicConnection+<OnStreamCapacityIncreased>d__33" ascii
        $s7 = "{0} Signaling StreamCapacityIncreased with {1} bidirectional increment (absolute value {2}) and {3} " wide
        $s8 = "ZSystem.Net.Quic.QuicConnection+SslConnectionOptions+<StartAsyncCertificateValidation>d__12" ascii
        $s9 = "/_/src/runtime/artifacts/obj/System.Net.Quic/Release/net10.0-windows/System.Net.Quic.pdb" ascii
        $s10 = ".System.Net.Quic.QuicStream+<DisposeAsync>d__45" ascii
        $s11 = "<GetExceptionForMsQuicStatus>g__GetExceptionInternal|4_0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
