rule Sightlines_tlsh_41cb624a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-41cb624a"
        date = "2026-10-31"
        campaign = "tlsh-41cb624a"
        family = ""
        hash = "47f6d55917ccaafa28480e692bf27e9dd95b5762b2c85398d575f65993bd2293"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-41cb624a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "<AppendUnknownChar>g__AppendNonAsciiBytes|47_0" ascii
        $s4 = "<NumberToBigInteger>g__DivideAndConquer|12_0" ascii
        $s5 = "<NumberToBigInteger>g__NaiveBase1E9ToBits|12_3" ascii
        $s6 = "<NumberToBigInteger>g__MultiplyAdd|12_4" ascii
        $s7 = "<BurnikelZieglerD3n2n>g__MultiplyActual|26_0" ascii
        $s8 = "<FormatBigIntegerToBinary>g__AppendByte|14_0" ascii
        $s9 = "System.Numerics.INumberBase<System.Numerics.Complex>.MultiplyAddEstimate" ascii
        $s10 = "System.Numerics.INumberBase<System.Numerics.BigInteger>.MultiplyAddEstimate" ascii
        $s11 = "<DivideBurnikelZiegler>g__Normalize|23_0" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
