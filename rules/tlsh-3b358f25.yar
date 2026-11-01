rule Sightlines_tlsh_3b358f25_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3b358f25"
        date = "2026-10-31"
        campaign = "tlsh-3b358f25"
        family = ""
        hash = "127361ac77186c2322e2fa5d75aac441c25eab9bd28ccb7799dfc0b06897db59"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3b358f25.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "&%'%(%)%*%+%,%.-32425298:8;8<8=8?>BACADAEAFAIHQPWV[Z\\Z^]_^`^a]b]ihkjrqsqtquqvqwqxqyqzq{q|q}q~q" wide
        $s1 = "bSystem.Net.Http.HttpConnection+<<CheckUsabilityOnScavenge>g__ReadAheadWithZeroByteReadAsync|39_0>d" ascii
        $s2 = "OSystem.Net.Http.Http3Connection+<>c__DisplayClass32_0+<<CheckForShutdown>b__0>d" ascii
        $s3 = "QSystem.Net.Http.HttpConnection+<CopyToUntilEofWithExistingBufferedDataAsync>d__92" ascii
        $s4 = "XSystem.Net.Http.HttpConnection+<<FillForHeadersAsync>g__ReadUntilEndOfHeaderAsync|83_0>d" ascii
        $s5 = "uSystem.Net.Http.Http3Connection+<>c__DisplayClass47_0+<<ProcessServerControlStreamAsync>g__ReadFram" ascii
        $s6 = "MSystem.Net.Http.HttpConnection+<<WriteAsync>g__AwaitFlushAndWriteAsync|71_0>d" ascii
        $s7 = "<CheckUsabilityOnScavenge>g__TransitionToCompletedAndTryOwnCompletion|39_1" ascii
        $s8 = "ASystem.Net.Http.Http3RequestStream+<SkipUnknownPayloadAsync>d__57" ascii
        $s9 = "vSystem.Net.Http.Http3Connection+<>c__DisplayClass47_0+<<ProcessServerControlStreamAsync>g__SkipUnkn" ascii
        $s10 = "ISystem.Net.Http.HttpConnection+<FlushThenWriteWithoutBufferingAsync>d__74" ascii
        $s11 = "CSystem.Net.Http.HttpConnectionPool+<EstablishProxyTunnelAsync>d__57" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3494512 and 12 of them
}
