rule Sightlines_tlsh_c020f964_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c020f964"
        date = "2026-10-31"
        campaign = "tlsh-c020f964"
        family = ""
        hash = "bb98698413fd83ccf898fff8d7d5763380f176914657dbe5ab2338716e500ef5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c020f964.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "BSystem.Net.ServerSentEvents.SseParser`1+<FillLineBufferAsync>d__38" ascii
        $s3 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s4 = "?System.Net.ServerSentEvents.SseFormatter+<WriteAsyncCore>d__3`1" ascii
        $s5 = "=System.Net.ServerSentEvents.SseParser`1+<EnumerateAsync>d__23" ascii
        $s6 = "System.Collections.Generic.IAsyncEnumerator<System.Net.ServerSentEvents.SseItem<T>>.MoveNextAsync" ascii
        $s7 = "System.Collections.Generic.IAsyncEnumerable<System.Net.ServerSentEvents.SseItem<T>>.GetAsyncEnumerat" ascii
        $s8 = "System.Collections.Generic.IAsyncEnumerator<System.Net.ServerSentEvents.SseItem<T>>.get_Current" ascii
        $s9 = "    <resource name=\"FxResources.System.Net.ServerSentEvents.SR.resources\" action=\"remove\" />" ascii
        $s10 = "  <assembly fullname=\"System.Net.ServerSentEvents\" feature=\"System.Resources.UseSystemResourceKeys\" " ascii
        $s11 = "ThrowArgumentException_CannotContainLineBreaks" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
