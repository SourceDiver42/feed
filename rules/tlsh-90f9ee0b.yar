rule Sightlines_tlsh_90f9ee0b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-90f9ee0b"
        date = "2026-10-31"
        campaign = "tlsh-90f9ee0b"
        family = ""
        hash = "4901b7f15d30d6463f08ed4221feb4c3330112240c35d7553490ba99da70c860"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-90f9ee0b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"false\"" ascii
        $s1 = "      <method signature=\"System.Boolean GetUsingResourceKeysSwitchValue()\" body=\"stub\" value=\"true\" " ascii
        $s2 = "      <method signature=\"System.Boolean UsingResourceKeys()\" body=\"stub\" value=\"false\" />" ascii
        $s3 = "<GetFullTypeNameLength>g__NeedsEscaping|5_1" ascii
        $s4 = "SystemEvents.EventsThreadShutdown callbacks are not run before the process exits. Use AppDomain.Proc" wide
        $s5 = "<GetFullTypeNameLength>g__GetUnescapedOffset|5_0" ascii
        $s6 = "QueryableMinByMaxByTSourceObsoleteDiagId" ascii
        $s7 = "The Queryable MinBy and MaxBy taking an IComparer<TSource> are obsolete. Use the new ones that take " wide
        $s8 = "KeyExchangeAlgorithm, KeyExchangeStrength, CipherAlgorithm, CipherStrength, HashAlgorithm and HashSt" wide
        $s9 = "<GetAssemblyNameCandidate>g__GetUnescapedOffset|8_0" ascii
        $s10 = "The constructors on Rfc2898DeriveBytes are obsolete. Use the static Pbkdf2 method instead." wide
        $s11 = "AuthenticationManager is not supported. Methods will no-op or throw PlatformNotSupportedException." wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2314864 and 12 of them
}
