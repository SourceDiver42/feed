rule Sightlines_tlsh_cfea823c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-cfea823c"
        date = "2026-10-31"
        campaign = "tlsh-cfea823c"
        family = ""
        hash = "60ea469ebda7911fcc9518e429fa468da7c8ba891808ca65f203f7611d754437"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-cfea823c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "#\"'&(&)&*&+&,&.-/-0-8797:7=<@?A?B?GFHFONPNQNRNSNTNUTVNXWZYdcecgfhfnm" wide
        $s1 = "JSystem.Net.HttpWebRequest+<>c__DisplayClass224_0+<<CreateHttpClient>b__1>d" ascii
        $s2 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s3 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s4 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s5 = "System.Diagnostics.Tracing.EventKeywords, System.Diagnostics.Tracing, Version=10.0.0.0, Culture=neut" ascii
        $s6 = "5System.Net.FtpWebRequest+<CreateConnectionAsync>d__85" ascii
        $s7 = "?System.Net.HttpWebResponse+TruncatedReadStream+<ReadAsync>d__18" ascii
        $s8 = ",System.Net.RequestStream+<DisposeAsync>d__27" ascii
        $s9 = "DOnly HTTP/1.0 and HTTP/1.1 version requests are currently supported.Q" ascii
        $s10 = "<System.Net.RequestStreamContent+<SerializeToStreamAsync>d__4" ascii
        $s11 = ":System.Net.HttpWebRequest+<InternalGetRequestStream>d__195" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
