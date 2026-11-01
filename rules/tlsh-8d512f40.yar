rule Sightlines_tlsh_8d512f40_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8d512f40"
        date = "2026-10-31"
        campaign = "tlsh-8d512f40"
        family = ""
        hash = "464900194cc2d5c405dba28b1b0ab02174fe224c2ea86ddf6ed4e48cea814e72"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8d512f40.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "OSystem.Net.Security.SslStream+<<WriteSingleChunk>g__WaitAndWriteAsync|166_0>d`1" ascii
        $s1 = "PSystem.Net.Security.SslStream+<<WriteSingleChunk>g__CompleteWriteAsync|166_1>d`1" ascii
        $s2 = "<ThrowIfExceptionalOrNotAuthenticatedOrShutdown>g__ThrowAlreadyShutdown|134_0" ascii
        $s3 = "BSystem.Net.Security.SslStream+<ReceiveHandshakeFrameAsync>d__160`1" ascii
        $s4 = "DSystem.Net.Security.SslStream+<ReplyOnReAuthenticationAsync>d__157`1" ascii
        $s5 = "9System.Net.Security.SslStream+<WriteAsyncChunked>d__165`1" ascii
        $s6 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s7 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s8 = "?System.Net.Security.SslStream+<EnsureFullTlsFrameAsync>d__170`1" ascii
        $s9 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s10 = "@System.Net.Security.SslStream+<ForceAuthenticationAsync>d__159`1" ascii
        $s11 = "System.Diagnostics.Tracing.EventKeywords, System.Diagnostics.Tracing, Version=10.0.0.0, Culture=neut" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1331728 and 12 of them
}
