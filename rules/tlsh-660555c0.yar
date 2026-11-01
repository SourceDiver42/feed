rule Sightlines_tlsh_660555c0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-660555c0"
        date = "2026-10-31"
        campaign = "tlsh-660555c0"
        family = ""
        hash = "0a59a95787ee15784d73079fdd5dc555b78659a6c560b6cbbf0d7452e638df89"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-660555c0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "=System.IO.Compression.BrotliStream+<<ReadAsync>g__Core|26_0>d" ascii
        $s1 = "8System.IO.Compression.BrotliStream+<FlushAsyncCore>d__15" ascii
        $s2 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s3 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s4 = "6System.IO.Compression.BrotliStream+<DisposeAsync>d__40" ascii
        $s5 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s6 = ">System.IO.Compression.BrotliStream+<WriteAsyncMemoryCore>d__12" ascii
        $s7 = "/_/src/runtime/artifacts/obj/System.IO.Compression.Brotli/Release/net10.0-windows/System.IO.Compress" ascii
        $s8 = "RepositoryUrl https://github.com/dotnet/dotnet" ascii
        $s9 = " Stream does not support writing.l" ascii
        $s10 = "BrotliEncoderMaxCompressedSize" ascii
        $s11 = ".NETCoreApp,Version=v10.0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
