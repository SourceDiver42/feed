rule Sightlines_imphash_8ae6d067_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-8ae6d067"
        date = "2026-10-22"
        campaign = "imphash-8ae6d067"
        family = ""
        hash = "072960b06dcec0b5d0991f98ff8b6bb90aa75ec4d0bf3ed7f58f1984ebc1dea4"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-8ae6d067.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "GCC: (MinGW-W64 x86_64-ucrt-posix-seh, built by Brecht Sanders, r1) 16.2.0" ascii
        $s1 = "  <asmv3:windowsSettings xmlns=\"http://schemas.microsoft.com/SMI/2016/WindowsSettings\">" ascii
        $s2 = " <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "    <requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/>" ascii
        $s4 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s5 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s6 = "   <longPathAware>true</longPathAware>" ascii
        $s7 = "Partial loss of significance (PLOSS)" ascii
        $s8 = "Total loss of significance (TLOSS)" ascii
        $s9 = "api-ms-win-crt-private-l1-1-0.dll" ascii
        $s10 = "Overflow range error (OVERFLOW)" ascii
        $s11 = "Argument domain error (DOMAIN)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 18874368 and 12 of them
}
